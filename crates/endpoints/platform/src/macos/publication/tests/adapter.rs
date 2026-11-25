use std::fs::{self, DirBuilder, File};
use std::io::{self, Write as _};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, symlink};
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
};

use crate::scratch::Scratch;

use super::super::super::staging::{
	ManagedStageGrant, ManagedStageRoot, MetadataReadyStage, StageBindingContext, StageDirectory,
};
use super::super::super::{ManagedReadGrant, ManagedReadRoot, acl};
use super::super::{PublishError, PublishRejection, PublishedObservationError};

const PAYLOAD: &[u8] = b"source bytes\0\xff";
const INCUMBENT: &[u8] = b"incumbent bytes";
const STAGE_DIRECTORY: &str = "private";
const STAGE_NAME: &str = "retained-stage";
const TARGET_NAME: &str = "target";
const SOURCE_NAME: &str = "source";

struct Fixture {
	destination: Scratch,
	source: Scratch,
	intent: Scratch,
}

impl Fixture {
	fn new() -> Self {
		let fixture = Self {
			destination: Scratch::new(),
			source: Scratch::new(),
			intent: Scratch::new(),
		};
		let stage = fixture.destination.path(STAGE_DIRECTORY);
		DirBuilder::new()
			.mode(0o700)
			.create(&stage)
			.expect("create synthetic stage directory");
		for directory in [
			fixture.destination.open(),
			fixture.source.open(),
			File::open(stage).expect("open synthetic stage directory"),
		] {
			acl::set_fixture_empty_acl(directory.as_fd())
				.expect("set explicit empty ACL on fixture");
		}
		write_new(&fixture.source.path(SOURCE_NAME), PAYLOAD);
		fixture
	}

	fn bind(&self) -> ManagedStageRoot {
		ManagedStageRoot::from_provisioned_directory(
			self.destination.open(),
			ManagedStageGrant::trusted_owner_authorizes_provisioned_root(),
		)
		.expect("hold exclusive fixture publication root")
	}

	fn ready_stage<'stage>(
		&self,
		directory: &'stage StageDirectory<'_>,
		stage_name: &'stage str,
		target_name: &'stage str,
	) -> MetadataReadyStage<'stage> {
		let mut stage = directory
			.create_file(
				name(stage_name),
				name(target_name),
				context(),
				u64::try_from(PAYLOAD.len()).expect("fixture extent fits u64"),
			)
			.expect("create private stage while target is absent");
		let source_root = ManagedReadRoot::from_provisioned_directory(
			self.source.open(),
			ManagedReadGrant::trusted_owner_authorizes_provisioned_root(),
		)
		.expect("hold source lease");
		let source = source_root
			.open_regular(name(SOURCE_NAME))
			.expect("hold original fixture read-only");
		source
			.check_basic_metadata()
			.expect("admit required source metadata");
		let mut source_bytes = [0; PAYLOAD.len()];
		source
			.read_exact_at(0, &mut source_bytes)
			.expect("read original fixture");
		assert_eq!(source_bytes.as_slice(), PAYLOAD);
		stage
			.write_next(&source_bytes)
			.expect("write independently allocated stage");
		let closed = stage
			.flush_and_close()
			.expect("synchronize and release sole writer");
		{
			let readback = closed
				.open_read_back()
				.expect("reopen the exact stage read-only");
			let mut bytes = [0; PAYLOAD.len()];
			readback
				.read_exact_at(0, &mut bytes)
				.expect("independently read back exact stage");
			readback
				.revalidate()
				.expect("verify stage observation and EOF");
			assert_eq!(bytes, source_bytes);
		}
		source.revalidate().expect("revalidate source and EOF");
		closed
			.apply_basic_metadata(&source)
			.expect("apply and verify required metadata on exact stage")
	}

	fn standard_stage<'stage>(
		&self,
		directory: &'stage StageDirectory<'_>,
	) -> MetadataReadyStage<'stage> {
		self.ready_stage(directory, STAGE_NAME, TARGET_NAME)
	}

	fn authorize(&self, binding: CopyBinding) -> PublishNoClobber {
		let mut session = CopySession::new(binding);
		for event in [
			CopyEvent::StagePrepared,
			CopyEvent::WritersJoined,
			CopyEvent::DataFlushed,
			CopyEvent::ReadbackVerified,
			CopyEvent::MetadataReady,
			CopyEvent::StageSealed,
		] {
			let _ = session
				.apply(binding, event)
				.expect("apply fixture prerequisite");
		}
		// This private fixture is synchronized before the real model issues
		// its token. A production coordinator must use its authoritative
		// journal with the exact stage, target and verification binding.
		let mut intent =
			File::create_new(self.intent.path("intent")).expect("allocate synthetic intent record");
		intent
			.write_all(b"test-only publication intent")
			.expect("write fixture intent");
		intent.sync_all().expect("synchronize fixture intent");
		rustix::fs::fsync(self.intent.open()).expect("synchronize fixture intent directory");
		let Some(CopyEffect::PublishNoClobber(authorization)) = session
			.apply(binding, CopyEvent::PublishIntentRecorded)
			.expect("record synchronized fixture intent")
		else {
			panic!("expected exclusive publication authorization");
		};
		authorization
	}
}

fn name(value: &str) -> UnixComponent<'_> {
	UnixComponent::new(value.as_bytes()).expect("valid synthetic name")
}

fn job_id() -> JobId {
	let mut bytes = [0; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	JobId::try_from_bytes(bytes).expect("use synthetic UUIDv7")
}

fn context() -> StageBindingContext {
	StageBindingContext::new(job_id(), EntryId::new(1), RunEpoch::new(1))
}

fn write_new(path: &Path, bytes: &[u8]) {
	File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.expect("exclusively create fixture file")
		.write_all(bytes)
		.expect("write fixture file");
}

fn identity(path: &Path) -> (u64, u64) {
	let stat = fs::symlink_metadata(path).expect("observe fixture without following");
	(stat.dev(), stat.ino())
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn verified_stage_is_published_under_its_bound_target() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root
		.open_stage_directory(name(STAGE_DIRECTORY))
		.expect("open provisioned stage directory");
	let ready = fixture.standard_stage(&directory);
	let stage_path = fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME);
	let source_path = fixture.source.path(SOURCE_NAME);
	let target_path = fixture.destination.path(TARGET_NAME);
	let old_stage = identity(&stage_path);
	let sealed_identity = ready
		.observe_identity()
		.expect("observe metadata-ready stage");
	let stage_directory = directory
		.observe_identity()
		.expect("observe held stage directory");
	let destination_directory = root.observe_identity().expect("observe held destination");
	let required = ready.metadata();
	let old_source = identity(&source_path);
	let authorization = fixture.authorize(ready.binding());
	assert_ne!(old_stage, old_source);

	let published = ready
		.publish_no_clobber(authorization)
		.expect("publish real authorized stage");
	assert_eq!(published.target_identity(), sealed_identity);
	assert_eq!(published.synced_stage_directory(), stage_directory);
	assert_eq!(
		published.synced_destination_directory(),
		destination_directory
	);

	assert!(
		matches!(stage_path.symlink_metadata(), Err(error) if error.kind() == io::ErrorKind::NotFound)
	);
	assert_eq!(identity(&target_path), old_stage);
	assert_eq!(identity(&source_path), old_source);
	let target = fs::symlink_metadata(&target_path).expect("observe published fixture metadata");
	assert_eq!(target.mode() & 0o7777, required.mode());
	assert_eq!(target.uid(), required.uid());
	assert_eq!(target.gid(), required.gid());
	assert_eq!(target.atime(), required.atime().seconds());
	assert_eq!(
		target.atime_nsec(),
		i64::from(required.atime().nanoseconds())
	);
	assert_eq!(target.mtime(), required.mtime().seconds());
	assert_eq!(
		target.mtime_nsec(),
		i64::from(required.mtime().nanoseconds())
	);
	assert_eq!(
		fs::read(target_path).expect("read published fixture"),
		PAYLOAD
	);
	assert_eq!(
		fs::read(source_path).expect("read unchanged source"),
		PAYLOAD
	);
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn rejects_mismatched_model_authorization_without_touching_names() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root
		.open_stage_directory(name(STAGE_DIRECTORY))
		.expect("open provisioned stage directory");
	let ready = fixture.standard_stage(&directory);
	let stage_path = fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME);
	let stage_before = identity(&stage_path);
	let wrong_epoch = CopyBinding::new(
		job_id(),
		EntryId::new(1),
		RunEpoch::new(2),
		exacopy_model::StageId::from_bytes(*ready.identity().stage_id_bytes()),
	);
	let error = ready
		.publish_with_barriers(fixture.authorize(wrong_epoch), |_| {
			panic!("no directory barrier before rename")
		})
		.expect_err("wrong epoch must not authorize publication");
	assert!(matches!(
		error,
		PublishError::Rejected {
			reason: PublishRejection::BindingMismatch,
			policy_error: None
		}
	));
	assert!(
		matches!(fixture.destination.path(TARGET_NAME).symlink_metadata(), Err(error) if error.kind() == io::ErrorKind::NotFound)
	);
	assert_eq!(identity(&stage_path), stage_before);
	assert_eq!(fs::read(stage_path).expect("read retained stage"), PAYLOAD);
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn rejects_rebound_private_name_and_preserves_both_objects() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root
		.open_stage_directory(name(STAGE_DIRECTORY))
		.expect("open provisioned stage directory");
	let ready = fixture.standard_stage(&directory);
	let authorization = fixture.authorize(ready.binding());
	let stage_path = fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME);
	let saved = fixture.destination.path(STAGE_DIRECTORY).join("saved");
	let before = identity(&stage_path);
	// Deliberately break fixture cooperation to exercise the final identity check.
	fs::rename(&stage_path, &saved).expect("rebind generated stage name");
	write_new(&stage_path, PAYLOAD);
	let rebind = identity(&stage_path);
	assert_ne!(before, rebind);

	assert!(matches!(
		ready.publish_with_barriers(authorization, |_| panic!("no barriers without rename")),
		Err(PublishError::Rejected {
			reason: PublishRejection::Stage(_),
			..
		})
	));
	assert!(
		matches!(fixture.destination.path(TARGET_NAME).symlink_metadata(), Err(error) if error.kind() == io::ErrorKind::NotFound)
	);
	assert_eq!(identity(&saved), before);
	assert_eq!(identity(&stage_path), rebind);
	assert_eq!(
		fs::read(saved).expect("read original retained stage"),
		PAYLOAD
	);
	assert_eq!(
		fs::read(stage_path).expect("read replacement fixture"),
		PAYLOAD
	);
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn late_regular_and_symlink_incumbents_retain_the_stage() {
	for late_link in [false, true] {
		let fixture = Fixture::new();
		let root = fixture.bind();
		let directory = root
			.open_stage_directory(name(STAGE_DIRECTORY))
			.expect("open provisioned stage directory");
		let ready = fixture.standard_stage(&directory);
		let authorization = fixture.authorize(ready.binding());
		let stage_path = fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME);
		let target_path = fixture.destination.path(TARGET_NAME);
		let referent_path = fixture.destination.path("referent");
		write_new(&referent_path, INCUMBENT);
		let referent = identity(&referent_path);
		let old_stage = identity(&stage_path);
		std::thread::scope(|scope| {
			scope
				.spawn(|| {
					if late_link {
						symlink("referent", &target_path)
							.expect("create late generated symbolic link");
					} else {
						write_new(&target_path, INCUMBENT);
					}
				})
				.join()
				.expect("join generated incumbent creator");
		});
		let old_target = identity(&target_path);
		let outcome = ready.publish_with_barriers(authorization, |_| {
			panic!("refused rename must not issue barriers")
		});
		match outcome {
			Err(PublishError::Conflict { policy_error: None }) => {}
			Err(PublishError::Uncertain {
				error,
				policy_error: None,
			}) if late_link && error.raw_os_error() == Some(libc::ELOOP) => {}
			outcome => panic!("late incumbent did not produce refusal: {outcome:?}"),
		}
		assert_eq!(identity(&stage_path), old_stage);
		assert_eq!(identity(&target_path), old_target);
		assert_eq!(identity(&referent_path), referent);
		assert_eq!(
			fs::read(stage_path).expect("read retained private stage"),
			PAYLOAD
		);
		assert_eq!(
			fs::read(target_path).expect("read retained target or referent"),
			INCUMBENT
		);
		if late_link {
			assert_eq!(
				fs::read_link(fixture.destination.path(TARGET_NAME))
					.expect("read retained symbolic link"),
				Path::new("referent")
			);
		}
	}
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn even_when_a_barrier_fails_both_are_attempted_and_rename_is_retained() {
	for fail_stage in [false, true] {
		let fixture = Fixture::new();
		let root = fixture.bind();
		let directory = root
			.open_stage_directory(name(STAGE_DIRECTORY))
			.expect("open provisioned stage directory");
		let ready = fixture.standard_stage(&directory);
		let target_path = fixture.destination.path(TARGET_NAME);
		let before = identity(&fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME));
		let stage_directory = identity(&fixture.destination.path(STAGE_DIRECTORY));
		let destination_directory = identity(&fixture.destination.path(""));
		let mut syncs = Vec::new();
		let authorization = fixture.authorize(ready.binding());
		let result = ready.publish_with_barriers(authorization, |directory| {
			let metadata = directory
				.metadata()
				.expect("observe attempted barrier inode");
			let id = (metadata.dev(), metadata.ino());
			syncs.push(id);
			if (id == stage_directory) == fail_stage {
				return Err(io::Error::from_raw_os_error(libc::EIO));
			}
			rustix::fs::fsync(directory).map_err(Into::into)
		});
		let Err(PublishError::Renamed {
			barriers: Some(barriers),
			observation: None,
			policy_error: None,
		}) = result
		else {
			panic!("rename evidence lost after directory failure: {result:?}");
		};
		assert_eq!(syncs, [stage_directory, destination_directory]);
		assert_eq!(barriers.stage().is_some(), fail_stage);
		assert_eq!(barriers.destination().is_some(), !fail_stage);
		assert_eq!(identity(&target_path), before);
		assert_eq!(
			fs::read(target_path).expect("read retained published file"),
			PAYLOAD
		);
	}
}

#[test]
#[ignore = "requires managed APFS fixtures without visible extended attributes"]
fn post_rename_rebinding_reports_observation_failure_after_both_barriers() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = root
		.open_stage_directory(name(STAGE_DIRECTORY))
		.expect("open provisioned stage directory");
	let ready = fixture.standard_stage(&directory);
	let target = fixture.destination.path(TARGET_NAME);
	let retained = fixture.destination.path("retained");
	let before = identity(&fixture.destination.path(STAGE_DIRECTORY).join(STAGE_NAME));
	let mut syncs = 0;
	let authorization = fixture.authorize(ready.binding());
	let result = ready.publish_with_barriers(authorization, |directory| {
		if syncs == 0 {
			// A deliberate fixture-only violation of the namespace lease.
			fs::rename(&target, &retained).expect("move the published fixture");
			write_new(&target, INCUMBENT);
		}
		syncs += 1;
		rustix::fs::fsync(directory).map_err(Into::into)
	});
	assert!(matches!(
		result,
		Err(PublishError::Renamed {
			barriers: None,
			observation: Some(PublishedObservationError::NamesChanged),
			policy_error: None,
		})
	));
	assert_eq!(syncs, 2);
	assert_eq!(identity(&retained), before);
	assert_eq!(
		fs::read(target).expect("read preserved subsequent incumbent"),
		INCUMBENT
	);
	assert_eq!(
		fs::read(retained).expect("read retained original publication"),
		PAYLOAD
	);
}

mod preservation;
