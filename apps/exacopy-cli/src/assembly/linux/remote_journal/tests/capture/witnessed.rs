//! Live SFTP and native retained-file comparison for one owned job, before reservation.

use std::fs;
use std::num::NonZeroU16;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::time::Duration;

use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_journal::StreamLength;
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, replay_remote_finalization_with_checkpoints,
};
use exacopy_platform::linux::{RetainedPrefixSelection, StageError};
use exacopy_sftp::{SftpSourceRequest, with_source};
use exacopy_transfer::remote_resume::prefix::{
	PrefixVerificationError, verify_held_retained_prefix,
};

use crate::assembly::linux::remote_continued::{WitnessPrefix, hold_original_witness_startup};
use crate::assembly::linux::remote_journal::CheckedResumeStartup;
use crate::assembly::remote_ssh::{admitted_at, generated_source};

use super::super::{
	QUALIFICATION, RemoteDownloadRoute, RemoteDownloadSource, RemoteSourceObservation, TARGET,
	epoch, job_name,
};
use super::{
	Fixture, LENGTH, NONCE, NativeCaptureStage, PrefixBarrier, STAGE, SourceEpoch, capture_live,
	component, source_epoch,
};

const PATH: &[u8] = b"owned-remote-subject";
const EXPANDED: u64 = LENGTH + 5;

#[tokio::test]
async fn held_native_donor_compares_a_live_positive_tail_and_refuses_a_changed_prefix() {
	let (session, key, calls) = generated_source(LENGTH, PATH, 0).await;
	// The test uses the real SSH/SFTP protocol over an in-process duplex stream.
	// This route label and the journal fixture's V1 qualification are fixture inputs.
	let authority =
		SshAuthority::new("sftp.example", NonZeroU16::new(22).unwrap(), "transfer").unwrap();
	let selected = RemoteDownloadSource::new(
		authority,
		key,
		RemoteDownloadRoute::ResolvedDirect {
			endpoint: "127.0.0.1:22".parse().unwrap(),
		},
		PATH,
	)
	.unwrap();
	let fixture = Fixture::with_source(selected, EXPANDED);
	let (mut supervisor, binding) = admitted_at(source_epoch());
	let path = [component(PATH).unwrap()];
	with_source(
		session,
		SftpSourceRequest {
			path: &path,
			epoch: source_epoch(),
			binding,
		},
		|current| supervisor.check_completion(Duration::ZERO, current),
		async |source| {
			let observed = source.observation();
			assert_eq!(observed.length, LENGTH);
			let observation = RemoteSourceObservation::new(
				StreamLength::new(observed.length).unwrap(),
				observed.mode,
				observed.modified,
			)
			.unwrap();
			let lease = fixture.open_bootstrap(fixture.bootstrap());
			let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
			let mut journal = lease.open_writer(&candidate).unwrap();
			let mut allocation = journal
				.allocate(&candidate, epoch(1), observation, NONCE)
				.unwrap();
			let bound = allocation.create(&mut journal).unwrap();
			let barrier = PrefixBarrier::new(bound.prefix_scope);
			let stage = NativeCaptureStage::new(
				bound.writer,
				lease.job(),
				bound.name,
				bound.target,
				bound.directory,
				bound.length,
				&barrier,
			)
			.unwrap();
			let mut checkpoints = journal.checkpoints(&barrier);
			let _ = capture_live(source, source_epoch(), stage, &mut checkpoints, &mut [0; 5])
				.await
				.unwrap();
		},
	)
	.await
	.unwrap();
	assert_eq!(&calls()[..3], &[1, 1, 1]);

	let stage = fixture.stage("capture-1");
	let owner = fixture.job_path().join("owner.cbor");
	let journal = fixture.segment();
	let selected_names = [&stage, &owner, &journal];
	let before = selected_names.map(|path| snapshot(path));
	let expected: Vec<u8> = (0..u8::try_from(EXPANDED).unwrap()).collect();
	assert_eq!(before[0].1, expected[..usize::try_from(LENGTH).unwrap()]);
	for (generation, byte_xor) in [(2, 0), (3, 1)] {
		compare(
			&fixture,
			SourceEpoch::new(epoch(generation)),
			byte_xor,
			&expected,
		)
		.await;
		assert_eq!(selected_names.map(|path| snapshot(path)), before);
		assert!(!fixture.target().try_exists().unwrap());
		assert!(!fixture.job_path().join("receipts").try_exists().unwrap());
	}
}

async fn compare(fixture: &Fixture, current_epoch: SourceEpoch, byte_xor: u8, expected: &[u8]) {
	let stage = component(STAGE).unwrap();
	let target = component(TARGET).unwrap();
	let job_name = job_name(fixture.job);
	let name = component(job_name.as_bytes()).unwrap();
	let job = fixture.root.open_recovery_job(name).unwrap();
	let shared = job.try_read_lease().unwrap();
	let owner_file = job.open_owner().unwrap();
	let mut segment = job.open_first_segment().unwrap();
	let key = fixture.profile.verification_key();
	let dialect = fixture.activation().dialect;
	let owner =
		super::super::super::lease::read_owner(&owner_file, &fixture.profile, dialect).unwrap();
	let trust = dialect.trust(&owner, fixture.profile.id(), &key).unwrap();
	let replay =
		replay_remote_finalization_with_checkpoints(&mut segment, &trust, QUALIFICATION, None)
			.unwrap();
	assert_eq!(replay.phase(), RemoteFinalizationPhase::Capture);
	assert!(replay.issue().is_none());
	let boundary = replay.boundary();
	assert_eq!(boundary.offset, segment.len());
	let startup = CheckedResumeStartup::new(shared, owner_file, segment, boundary);
	let startup = hold_original_witness_startup(startup, &replay, target).unwrap();
	let active = replay.active_checkpoints().unwrap();
	let history = active.prefix_history().unwrap();
	assert_eq!(history.covered_extent(), LENGTH);
	assert_eq!(history.ranges().count(), 1);
	let prepared = history.prepared();

	startup.recheck().unwrap();
	let (session, observed_key, calls) = generated_source(EXPANDED, PATH, byte_xor).await;
	assert_eq!(&observed_key, fixture.scope.source.host_key_sha256());
	assert!(matches!(
		fixture.root.try_recovery_write_lease(name, job.identity()),
		Err(StageError::JobBusy)
	));
	let held = startup
		.open_witnessed(&fixture.root, &fixture.profile, fixture.job, &fixture.scope)
		.unwrap();
	let inventory = held.lease.job().inventory(stage, target).unwrap();
	held.check_donor(&inventory).unwrap();
	let reader = held
		.lease
		.read_retained_prefix(
			&inventory,
			RetainedPrefixSelection {
				stage,
				target,
				directory: exacopy_endpoint::linux_job::JobFileIdentity {
					device: prepared.directory.device(),
					inode: prepared.directory.inode(),
				},
				file: exacopy_endpoint::linux_job::JobFileIdentity {
					device: prepared.file.device(),
					inode: prepared.file.inode(),
				},
			},
		)
		.unwrap();
	let path = [component(PATH).unwrap()];
	let (mut supervisor, binding) = admitted_at(current_epoch);
	with_source(
		session,
		SftpSourceRequest {
			path: &path,
			epoch: current_epoch,
			binding,
		},
		|current| supervisor.check_completion(Duration::ZERO, current),
		async move |source| {
			let compared = verify_held_retained_prefix(
				&history,
				source,
				current_epoch,
				WitnessPrefix(reader),
				&mut [0; 8],
			)
			.await;
			if byte_xor != 0 {
				assert!(matches!(
					compared,
					Err(PrefixVerificationError::SourceMismatch { offset: 0 })
				));
				return;
			}
			let compared = compared.unwrap();
			assert_eq!(compared.prefix().boundary(), boundary);
			assert_eq!(compared.prefix().extent(), LENGTH);
			let mut continuation = compared.into_continuation();
			let mut suffix = Vec::new();
			let mut scratch = [0; 3];
			while let Some(bytes) = continuation.read_next(&mut scratch).await.unwrap() {
				suffix.extend_from_slice(bytes);
			}
			assert_eq!(suffix, expected[usize::try_from(LENGTH).unwrap()..]);
			let full = continuation.finish().await.unwrap();
			assert_eq!(full.epoch(), current_epoch);
			assert_eq!(full.length(), EXPANDED);
			assert_eq!(&full.digest(), blake3::hash(expected).as_bytes());
		},
	)
	.await
	.unwrap();
	if byte_xor == 0 {
		assert_eq!(&calls()[..3], &[1, 1, 1]);
	} else {
		assert_eq!(calls(), [1, 0, 0, 7]);
	}
	held.check_donor(&inventory).unwrap();
	drop(held.open_segment().unwrap());
}

fn snapshot(path: &Path) -> ((u64, u64, u64, i64, i64, i64, i64), Vec<u8>) {
	let stat = fs::metadata(path).unwrap();
	(
		(
			stat.dev(),
			stat.ino(),
			stat.nlink(),
			stat.mtime(),
			stat.mtime_nsec(),
			stat.ctime(),
			stat.ctime_nsec(),
		),
		fs::read(path).unwrap(),
	)
}
