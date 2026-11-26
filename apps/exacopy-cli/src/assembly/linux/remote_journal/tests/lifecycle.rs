use std::fs::{self, OpenOptions};
use std::num::NonZeroU64;
use std::os::unix::fs::OpenOptionsExt as _;

use exacopy_journal::frame::{ChainHead, FrameWriter};
use exacopy_journal::remote_download::finalization::{
	RemoteFinalizationBinding, RemoteFinalizationBody as Final, RemoteFinalizationRecord,
	RemoteLocalMetadata, RemotePublishTarget,
};
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationPhase as Phase;
use exacopy_journal::remote_download::{RemoteDownloadOwnerRecord, RemoteDownloadRoute};
use exacopy_journal::{StreamDigest, StreamLength};

use super::super::ledger::context;
use super::{
	Error, Fixture, FixtureGrant, LENGTH, NONCE, QUALIFICATION, RemoteJobLease, STAGE, component,
	epoch, observation,
};

const DATA: &[u8] = b"native stream";
const FRESH: &[u8] = b"capture-next";

#[test]
fn unsupported_route_grant_and_policy_refuse_before_a_job_exists() {
	let legacy = Fixture::with_route(RemoteDownloadRoute::Direct);
	assert!(matches!(
		legacy.activate(&legacy.scope, &legacy.grant),
		Err(Error::UnsupportedRoute)
	));
	assert!(!legacy.job_path().exists());

	let fixture = Fixture::new();
	let mut scope = fixture.scope.clone();
	scope.metadata_policy = [0x57; 32];
	let grant = FixtureGrant::new(&scope);
	assert!(matches!(
		fixture.activate(&scope, &grant),
		Err(Error::Metadata(_))
	));
	scope.maximum_extent = StreamLength::new(LENGTH - 1).unwrap();
	scope.metadata_policy = fixture.scope.metadata_policy;
	assert!(matches!(
		fixture.activate(&scope, &fixture.grant),
		Err(Error::Binding)
	));

	fixture
		.qualification
		.route
		.set(super::RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1);
	assert!(matches!(
		fixture.activate(&fixture.scope, &fixture.grant),
		Err(Error::UnsupportedRoute)
	));
	fixture
		.qualification
		.route
		.set(super::RemoteQualificationRouteClass::DirectPinnedTcpV1);
	let activation = fixture.activation();
	fixture.grant.digest.set([0x97; 32]);
	assert!(matches!(
		super::bootstrap(
			&fixture.profile,
			fixture.job,
			super::OwnerTimestamp::new(1, 0).unwrap(),
			super::OwnerToken::from_bytes([0x51; 16]).unwrap(),
			activation,
		),
		Err(Error::BootstrapNotCreated(cause)) if matches!(*cause, Error::Binding)
	));
	assert!(!fixture.job_path().exists());
	assert!(!fixture.target().exists());
}

#[test]
fn the_approved_route_selects_one_owner_dialect_at_bootstrap_and_recovery() {
	let direct = Fixture::new();
	direct.bootstrap();
	let path = direct.job_path().join("owner.cbor");
	let bytes = fs::read(path).unwrap();
	let key = direct.profile.verification_key();
	assert!(RemoteDownloadOwnerRecord::decode(&bytes, direct.profile.id(), &key).is_err());
	RemoteDownloadOwnerRecord::decode_resolved_direct(&bytes, direct.profile.id(), &key).unwrap();
	reopen(&direct).unwrap();

	let embedded = Fixture::with_route(RemoteDownloadRoute::EmbeddedWireGuard {
		peer: [0x44; 32],
		revision: [0x45; 32],
		inner: "10.8.0.2:22".parse().unwrap(),
	});
	embedded.bootstrap();
	let path = embedded.job_path().join("owner.cbor");
	let bytes = fs::read(path).unwrap();
	let key = embedded.profile.verification_key();
	assert!(
		RemoteDownloadOwnerRecord::decode_resolved_direct(&bytes, embedded.profile.id(), &key)
			.is_err()
	);
	RemoteDownloadOwnerRecord::decode(&bytes, embedded.profile.id(), &key).unwrap();
	reopen(&embedded).unwrap();
}

#[test]
fn a_synced_retirement_is_required_before_a_fresh_allocation() {
	let fixture = Fixture::new();
	let sealed = prepare(&fixture, false);
	let lease = reopen(&fixture).unwrap();
	let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
	assert!(matches!(
		lease.open_writer(&candidate),
		Err(Error::Lifecycle {
			phase: Phase::Sealed,
			..
		})
	));
	let mut writer = lease.retire_and_open_writer(&candidate).unwrap();
	let new = writer
		.allocate(&candidate, epoch(2), observation(), [0x62; 16])
		.unwrap();
	drop(new);
	drop(writer);
	let frames = fs::read(fixture.segment()).unwrap();
	let mut reader =
		exacopy_journal::frame::FrameReader::new(frames.as_slice(), ChainHead::start());
	let mut kinds = Vec::new();
	while let Some(frame) = reader.next_frame().unwrap() {
		if frame.head().sequence() > sealed.sequence() {
			kinds.push(frame.kind());
		}
	}
	assert_eq!(
		kinds,
		[
			exacopy_journal::frame::FrameKind::RemoteCaptureRetired,
			exacopy_journal::frame::FrameKind::RemoteStageAllocated,
		]
	);
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), DATA);
	assert!(!fixture.stage("capture-next").exists());
	assert!(!fixture.target().exists());
}

#[test]
fn a_retired_job_requires_the_same_live_grant_before_any_allocation() {
	let fixture = Fixture::new();
	prepare(&fixture, false);
	{
		let lease = reopen(&fixture).unwrap();
		let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
		drop(lease.retire_and_open_writer(&candidate).unwrap());
	}
	let ledger = fs::read(fixture.segment()).unwrap();
	fixture.grant.digest.set([0x19; 32]);
	assert!(matches!(reopen(&fixture), Err(Error::Binding)));
	assert_eq!(fs::read(fixture.segment()).unwrap(), ledger);
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), DATA);
	assert!(!fixture.stage("capture-next").exists());
}

#[test]
fn retirement_refuses_a_rebound_old_allocated_name_under_the_same_lease() {
	let fixture = Fixture::new();
	prepare(&fixture, false);
	let lease = reopen(&fixture).unwrap();
	let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
	let ledger = fs::read(fixture.segment()).unwrap();
	let original = fixture.stage("capture-1");
	let preserved = fixture.stage("retained-original");
	fs::rename(&original, &preserved).unwrap();
	let mut substitute = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&original)
		.unwrap();
	std::io::Write::write_all(&mut substitute, DATA).unwrap();
	assert!(matches!(
		lease.retire_and_open_writer(&candidate),
		Err(Error::UnknownStage)
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), ledger);
	assert_eq!(fs::read(preserved).unwrap(), DATA);
	assert!(!fixture.stage("capture-next").exists());
}

#[test]
fn a_post_intent_occupied_target_stays_in_effect_reconciliation() {
	let fixture = Fixture::new();
	let intent = prepare(&fixture, true);
	fs::write(fixture.target(), b"incumbent").unwrap();
	let ledger = fs::read(fixture.segment()).unwrap();
	assert!(matches!(
		reopen(&fixture),
		Err(Error::Lifecycle { phase: Phase::Intent, boundary, issue: None }) if boundary.head == intent
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), ledger);
	assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), DATA);
}

fn reopen(fixture: &Fixture) -> Result<RemoteJobLease<'_>, Error> {
	RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation())
}

fn prepare(fixture: &Fixture, intent: bool) -> ChainHead {
	{
		let lease = fixture.open_bootstrap(fixture.bootstrap());
		let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
		let mut journal = lease.open_writer(&candidate).unwrap();
		let mut allocation = journal
			.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
			.unwrap();
		let mut stage = allocation.create(&mut journal).unwrap().writer;
		stage.write_all_at(0, DATA).unwrap();
		stage.flush().unwrap();
		let closed = stage.close_writes().unwrap();
		let mut observed = [0; LENGTH as usize];
		closed.read_exact_at(0, &mut observed).unwrap();
		assert_eq!(observed.as_slice(), DATA);
	}
	let capture = fixture.replay();
	let attempt = capture.attempts().last().unwrap();
	let prepared = attempt.prepared().unwrap();
	let owner = fs::read(fixture.job_path().join("owner.cbor")).unwrap();
	let key = fixture.profile.verification_key();
	let owner = fixture
		.activation()
		.dialect
		.decode(&owner, fixture.profile.id(), &key)
		.unwrap();
	let binding = RemoteFinalizationBinding {
		context: context(&owner),
		prepared: prepared.head,
		epochs: attempt.epochs(),
		stage: prepared.file,
	};
	let file = OpenOptions::new()
		.append(true)
		.open(fixture.segment())
		.unwrap();
	let mut writer = FrameWriter::new(file, capture.boundary().head);
	let mut append = |body: Final<'_>| {
		let payload = RemoteFinalizationRecord::new(binding, writer.head(), body)
			.unwrap()
			.encode()
			.unwrap();
		writer.append(body.kind(), &payload).unwrap()
	};
	let length = StreamLength::new(LENGTH).unwrap();
	let seal = append(Final::StageSealed {
		directory: prepared.directory,
		length,
	});
	let end = if intent {
		let digest = StreamDigest::from_bytes(*blake3::hash(DATA).as_bytes());
		let verification = append(Final::VerificationRecorded {
			length,
			source: digest,
			stage: digest,
		});
		append(Final::MetadataRecorded(RemoteLocalMetadata {
			uid: 1000,
			gid: 1000,
		}));
		let destination = &fixture.scope.destination;
		append(Final::PublishIntent {
			seal,
			verification,
			directory: prepared.directory,
			target: RemotePublishTarget {
				root: destination.root(),
				parent: destination.parent(),
				component: component(destination.target()).unwrap(),
			},
			qualification: QUALIFICATION,
		})
	} else {
		seal
	};
	writer.into_inner().sync_all().unwrap();
	end
}

#[test]
fn initial_and_explicit_resume_recheck_grant_at_stage_allocation() {
	for initial in [true, false] {
		let fixture = Fixture::new();
		let created = fixture.bootstrap();
		let lease = if initial {
			fixture.open_bootstrap(created)
		} else {
			reopen(&fixture).unwrap()
		};
		let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
		let mut writer = lease.open_writer(&candidate).unwrap();
		let before = fs::read(fixture.segment()).unwrap();
		fixture.grant.refuse_after(0);
		assert!(matches!(
			writer.allocate(&candidate, epoch(1), observation(), NONCE),
			Err(Error::Grant(_))
		));
		assert_eq!(fs::read(fixture.segment()).unwrap(), before);
		assert!(!fixture.stage("capture-next").exists());
		assert!(!fixture.target().exists());
	}
}

#[test]
fn explicit_retirement_checks_grant_after_the_resume_barrier() {
	let fixture = Fixture::new();
	let _ = prepare(&fixture, false);
	let lease = reopen(&fixture).unwrap();
	let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
	let before = fs::read(fixture.segment()).unwrap();
	fixture.grant.refuse_after(1);
	assert!(matches!(
		lease.retire_and_open_writer(&candidate),
		Err(Error::Grant(_))
	));
	assert_eq!(fs::read(fixture.segment()).unwrap(), before);
	assert_eq!(fs::read(fixture.stage("capture-1")).unwrap(), DATA);
	assert!(!fixture.stage("capture-next").exists());
	assert!(!fixture.target().exists());
}
