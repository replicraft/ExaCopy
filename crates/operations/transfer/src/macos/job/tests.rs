use std::fs::{self, DirBuilder, File};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU32, Ordering};

use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, FrameReader};
use exacopy_journal::{
	DarwinEntryPrepared, JournalEntryId, JournalEpoch, JournalJobId, ObservedTimestamp,
	TargetObservation,
};
use exacopy_platform::macos::staging::jobs::{JobArtifact, JobError};
use exacopy_platform::macos::staging::{ManagedStageGrant, ManagedStageRoot, StageError};
use exacopy_platform::macos::{BasicMetadataError, ManagedReadError, ManagedReadGrant};

use super::*;
use crate::macos::plan::{DestinationPlanBinding, PlanAttempt, SourceMetadata, SourcePlanBinding};

const SOURCE: &str = "source";
const TARGET: &str = "target";
const PRIVATE: &str = "private";
const FIRST_SEGMENT: &str = "journal/00000000000000000001.exajnl";
const PAYLOAD: &[u8] = b"source contents must survive bootstrap";

#[test]
fn admitted_fixture_keeps_both_leases_and_persists_exact_evidence() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
	let path = fixture.0.join(PRIVATE).join(name.to_string());
	// Exercise actual private creation and Darwin barriers with known plan inputs.
	// Source metadata checks are exercised separately because this host may attach
	// com.apple.provenance to every fixture file.
	let destination = admit_destination(plan.destination(), request).unwrap();
	let prepare = || {
		with_admitted_job(&plan, request, name, destination, |job| {
			assert_eq!(job.name(), name);
			assert_eq!(job.initial_frame().kind(), FrameKind::JobPrepared);
			assert_eq!(
				job.initial_frame().barrier(),
				JournalFileBarrier::DarwinFullFsync
			);
			assert!(matches!(open_root(&path), Err(StageError::DirectoryBusy)));
			assert!(matches!(
				open_root(&path.join("journal")),
				Err(StageError::DirectoryBusy)
			));
			let bytes = fs::read(path.join("owner.cbor")).unwrap();
			let owner =
				DarwinOwnerRecord::decode(&bytes, request.profile.id, &signer.verifying_key())
					.unwrap();
			assert_eq!(&owner, job.owner());
			assert_eq!(
				owner.manifest().state_root,
				native_identity(job.job.identity()).unwrap()
			);
			assert_eq!(owner.manifest().plan_digest, plan.digest());
			assert_eq!(fs::read(path.join("plan.cbor")).unwrap(), plan.encode());
			let mut reader = FrameReader::new(
				File::open(path.join(FIRST_SEGMENT)).unwrap(),
				ChainHead::start(),
			);
			let frame = reader.next_frame().unwrap().unwrap();
			let parsed = DarwinJobPrepared::from_frame(&frame).unwrap();
			assert_eq!(&parsed, job.preparation());
			assert_eq!(parsed.context(), plan.context());
			assert_eq!(parsed.destination_root(), destination);
			parsed.validate_owner(&owner).unwrap();
			assert!(reader.next_frame().unwrap().is_none());
		})
	};
	prepare().unwrap();
	assert!(open_root(&path).is_ok());
	assert!(open_root(&path.join("journal")).is_ok());
	let segment_before = fs::read(path.join(FIRST_SEGMENT)).unwrap();
	assert!(
		matches!(prepare(), Err(JobBootstrapError::Create(JobError::Occupied { job, artifact: JobArtifact::Directory })) if job == name)
	);
	assert_eq!(fs::read(path.join(FIRST_SEGMENT)).unwrap(), segment_before);
	assert_eq!(fs::read(fixture.0.join(SOURCE)).unwrap(), PAYLOAD);
	assert!(!fixture.0.join(TARGET).exists());
	assert!(!path.join("stage").exists());
}

#[test]
fn refuses_untrusted_inputs_and_an_incumbent_before_creating_private_state() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let wrong_profile = DarwinJobProfile {
		id: OwnerProfileId::from_bytes([5; 16]).unwrap(),
		..request.profile
	};
	let never = |_: &mut PreparedDarwinJob<'_>| panic!("rejected job reached its operation");
	assert!(matches!(
		with_prepared_job(
			&plan,
			JobBootstrap {
				profile: wrong_profile,
				..request
			},
			never
		),
		Err(JobBootstrapError::Admission(
			JobAdmissionError::ProfileMismatch
		))
	));
	let wrong_grant = root_id([11; 16]);
	assert!(matches!(
		with_prepared_job(
			&plan,
			JobBootstrap {
				destination_root_id: wrong_grant,
				..request
			},
			never
		),
		Err(JobBootstrapError::Admission(
			JobAdmissionError::DestinationMismatch
		))
	));
	assert!(matches!(
		with_prepared_job(
			&plan,
			JobBootstrap {
				source_root_id: wrong_grant,
				..request
			},
			never
		),
		Err(JobBootstrapError::Admission(
			JobAdmissionError::SourceMismatch
		))
	));
	let target = fixture.0.join(TARGET);
	symlink("missing", &target).unwrap();
	assert!(matches!(
		with_prepared_job(&plan, request, never),
		Err(JobBootstrapError::Admission(
			JobAdmissionError::Destination(JobError::Managed(StageError::NameCollision))
		))
	));
	assert_eq!(fs::read_link(target).unwrap(), Path::new("missing"));
	fixture.assert_no_job();
}

#[test]
fn refuses_extended_attributes_before_creating_private_state() {
	let fixture = Fixture::new();
	assert!(
		Command::new("/usr/bin/xattr")
			.args(["-w", "com.example.exacopy-bootstrap", "fixture"])
			.arg(fixture.0.join(SOURCE))
			.status()
			.unwrap()
			.success()
	);
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	assert!(matches!(
		with_prepared_job(&plan, request, |_| panic!(
			"unsupported source reached preparation"
		)),
		Err(JobBootstrapError::Admission(JobAdmissionError::Source(
			ManagedReadError::BasicMetadata(BasicMetadataError::ExtendedAttributes)
		)))
	));
	fixture.assert_no_job();
	assert_eq!(fs::read(fixture.0.join(SOURCE)).unwrap(), PAYLOAD);
	assert!(!fixture.0.join(TARGET).exists());
}

#[test]
fn admitted_entry_synchronizes_exact_kind_2_before_exposing_the_empty_stage() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
	let path = fixture.0.join(PRIVATE).join(name.to_string());
	let destination = admit_destination(plan.destination(), request).unwrap();
	with_admitted_job(&plan, request, name, destination, |job| {
		let predecessor = job.initial_frame().head();
		job.with_admitted_entry(|entry| {
			assert_eq!(entry.job_name(), name);
			assert_eq!(
				entry.synced().barrier(),
				JournalFileBarrier::DarwinFullFsync
			);
			assert_eq!(entry.synced().kind(), FrameKind::EntryPrepared);
			assert_eq!(entry.synced().head(), entry.frame().head());
			assert_eq!(entry.frame().previous_digest(), predecessor.digest());
			assert_eq!(entry.frame().head().sequence(), 2);
			let record = entry.preparation();
			assert_eq!(record.entry(), plan.attempt().entry);
			assert_eq!(record.context(), plan.context());
			assert_eq!(
				record.preparation().source.identity(),
				plan.source().file_identity
			);
			assert_eq!(record.preparation().source.length(), plan.source().length);
			assert_eq!(
				record.preparation().source.component(),
				plan.source().component
			);
			assert_eq!(
				record.preparation().target_component,
				plan.destination().component
			);
			assert_eq!(
				record.target_observation(),
				TargetObservation::AbsentObserved
			);
			let stage = path.join("stage");
			assert!(matches!(open_root(&stage), Err(StageError::DirectoryBusy)));
			let stage_file = fs::metadata(stage.join("payload")).unwrap();
			assert_eq!(stage_file.len(), 0);
			assert_eq!(
				stage_file.ino(),
				record.preparation().stage.identity.inode().get()
			);
			assert_eq!(record.preparation().stage.component.as_bytes(), b"payload");
			let mut reader = FrameReader::new(
				File::open(path.join(FIRST_SEGMENT)).unwrap(),
				ChainHead::start(),
			);
			let first = reader.next_frame().unwrap().unwrap();
			assert_eq!(first.head(), predecessor);
			let actual = reader.next_frame().unwrap().unwrap();
			assert_eq!(&actual, entry.frame());
			assert_eq!(&DarwinEntryPrepared::from_frame(&actual).unwrap(), record);
			assert!(reader.next_frame().unwrap().is_none());
		})
		.unwrap();
		let duplicate = job
			.with_admitted_entry(|_| panic!("second preparation was admitted"))
			.unwrap_err();
		assert_eq!(duplicate.job(), name);
		assert!(matches!(
			duplicate.failure(),
			EntryPreparationFailure::AlreadyAttempted
		));
	})
	.unwrap();
	assert_eq!(fs::read(fixture.0.join(SOURCE)).unwrap(), PAYLOAD);
	assert!(!fixture.0.join(TARGET).exists());
	assert!(open_root(&path.join("stage")).is_ok());
}

#[test]
fn entry_preparation_refuses_source_rebinding_after_kind_1() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
	let path = fixture.0.join(PRIVATE).join(name.to_string());
	let destination = admit_destination(plan.destination(), request).unwrap();
	with_admitted_job(&plan, request, name, destination, |job| {
		let retained_source = fixture.0.join("retained-source");
		fs::rename(fixture.0.join(SOURCE), &retained_source).unwrap();
		let refusal = job
			.with_prepared_entry(|_| panic!("rebound source reached its operation"))
			.unwrap_err();
		assert_eq!(refusal.job(), name);
		assert!(matches!(
			refusal.failure(),
			EntryPreparationFailure::Source(JobAdmissionError::Source(
				ManagedReadError::SourceChanged
			))
		));
		assert_eq!(fs::read(retained_source).unwrap(), PAYLOAD);
		assert!(!path.join("stage").exists());
		let mut reader = FrameReader::new(
			File::open(path.join(FIRST_SEGMENT)).unwrap(),
			ChainHead::start(),
		);
		assert!(reader.next_frame().unwrap().is_some());
		assert!(reader.next_frame().unwrap().is_none());
	})
	.unwrap();
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static NEXT: AtomicU32 = AtomicU32::new(0);
		let path = Path::new("/private/tmp").join(format!(
			"exacopy-apfs-bootstrap-{}-{}",
			process::id(),
			NEXT.fetch_add(1, Ordering::Relaxed)
		));
		DirBuilder::new().mode(0o700).create(&path).unwrap();
		let fixture = Self(path);
		let helper = fixture.0.join("empty-acl");
		let source = Path::new(env!("CARGO_MANIFEST_DIR"))
			.join("../../clients/cli/tests/fixtures/macos_empty_acl.c");
		assert!(
			Command::new("/usr/bin/cc")
				.args(["-Wall", "-Wextra", "-Werror"])
				.arg(source)
				.arg("-o")
				.arg(&helper)
				.status()
				.unwrap()
				.success()
		);
		let private = fixture.0.join(PRIVATE);
		DirBuilder::new().mode(0o700).create(&private).unwrap();
		for directory in [&fixture.0, &private] {
			assert!(
				Command::new(&helper)
					.arg(directory)
					.status()
					.unwrap()
					.success()
			);
		}
		use std::io::Write as _;
		File::options()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(fixture.0.join(SOURCE))
			.unwrap()
			.write_all(PAYLOAD)
			.unwrap();
		fixture
	}

	fn root(&self) -> ManagedStageRoot {
		open_root(&self.0).unwrap()
	}

	fn source<'root>(&self, root: &'root ManagedStageRoot) -> ManagedRegularFile<'root> {
		root.open_regular_source(
			&self.0,
			component(SOURCE),
			ManagedReadGrant::trusted_owner_authorizes_provisioned_root(),
		)
		.unwrap()
	}

	fn request<'held, 'profile>(
		&self,
		source: &'held ManagedRegularFile<'held>,
		container: &'held StageDirectory<'held>,
		signer: &'profile SigningKey,
	) -> JobBootstrap<'held, 'profile> {
		JobBootstrap {
			source,
			source_root_id: root_id([1; 16]),
			container,
			destination_root_id: root_id([1; 16]),
			profile: DarwinJobProfile {
				id: OwnerProfileId::from_bytes([2; 16]).unwrap(),
				signer,
				created: OwnerTimestamp::new(20, 0).unwrap(),
				owner_token: OwnerToken::from_bytes([3; 16]).unwrap(),
			},
		}
	}

	fn plan(
		&self,
		root: &ManagedStageRoot,
		request: JobBootstrap<'_, '_>,
	) -> DarwinCopyPlan<'static> {
		let identities = request.source.observe_identities().unwrap();
		let stat = fs::metadata(self.0.join(SOURCE)).unwrap();
		let make_time = |seconds, nanoseconds| {
			ObservedTimestamp::new(seconds, u32::try_from(nanoseconds).unwrap()).unwrap()
		};
		let metadata = SourceMetadata::new(
			u16::try_from(stat.mode() & 0o7777).unwrap(),
			stat.uid(),
			stat.gid(),
			make_time(stat.atime(), stat.atime_nsec()),
			make_time(stat.mtime(), stat.mtime_nsec()),
			make_time(stat.ctime(), stat.ctime_nsec()),
		)
		.unwrap();
		let mut job = [0; 16];
		job[6] = 0x70;
		job[8] = 0x80;
		DarwinCopyPlan::new(
			PlanAttempt {
				job: JournalJobId::from_bytes(job).unwrap(),
				epoch: JournalEpoch::new(1),
				entry: JournalEntryId::from_bytes([5; 16]),
				profile: request.profile.id,
			},
			SourcePlanBinding {
				root_id: request.source_root_id,
				root_identity: native_identity(identities.parent).unwrap(),
				file_identity: native_identity(identities.file).unwrap(),
				length: request.source.length(),
				metadata,
				component: component(SOURCE),
			},
			DestinationPlanBinding {
				root_id: request.destination_root_id,
				root_identity: native_identity(root.observe_identity().unwrap()).unwrap(),
				component: component(TARGET),
			},
		)
		.unwrap()
	}

	fn assert_no_job(&self) {
		assert!(fs::read_dir(self.0.join(PRIVATE)).unwrap().next().is_none());
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

fn open_root(path: &Path) -> Result<ManagedStageRoot, StageError> {
	ManagedStageRoot::from_provisioned_directory(
		File::open(path).unwrap(),
		ManagedStageGrant::trusted_owner_authorizes_provisioned_root(),
	)
}

fn root_id(mut bytes: [u8; 16]) -> RootCapabilityId {
	bytes[6] = 0x40;
	bytes[8] = 0x80;
	RootCapabilityId::from_bytes(bytes).unwrap()
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).unwrap()
}
