use exacopy_journal::frame::FrameWriter;
use exacopy_journal::{
	DarwinStageSealed, DarwinStreamEvidence, DarwinVerificationRecorded, StreamDigest, StreamLength,
};
use exacopy_platform::macos::staging::MAX_STAGE_IO_BYTES;
use exacopy_platform::macos::staging::jobs::{RecoveryError, RecoveryJob};

use super::*;
use crate::assembly::macos::inspection::{
	DarwinInspectionAuthority, DarwinInspectionError, DarwinReceiptArtifact,
	DarwinStageReadBackError, inspect_job, inspect_job_with_stage_read_back,
};
use crate::assembly::macos::replay::{DarwinJournalTail, DarwinReplayStatus};

#[test]
fn reopened_job_binds_trusted_destination_and_keeps_live_names_separate_from_history() {
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
	let stage = with_admitted_job(&plan, request, name, destination, |job| {
		job.with_admitted_entry(|entry| entry.preparation().preparation().stage.identity)
			.unwrap()
	})
	.unwrap();
	let journal_before = fs::read(path.join(FIRST_SEGMENT)).unwrap();
	let incumbent = b"existing public contents";
	fs::write(fixture.0.join(TARGET), incumbent).unwrap();

	let recovery = container.open_recovery_job(name).unwrap();
	let authority = DarwinInspectionAuthority {
		profile: request.profile.id,
		key: &signer.verifying_key(),
		destination_root: request.destination_root_id,
	};
	let inspected = inspect_job(&recovery, authority).unwrap();
	assert_eq!(inspected.plan_bytes, plan.encode());
	assert_eq!(inspected.replay.status(), DarwinReplayStatus::Incomplete);
	assert_eq!(inspected.replay.tail(), DarwinJournalTail::Clean);
	assert_eq!(
		inspected.replay.boundary().offset,
		u64::try_from(journal_before.len()).unwrap()
	);
	assert_eq!(inspected.receipt, DarwinReceiptArtifact::Missing);
	assert!(inspected.stage_directory.is_some());
	let observed_stage = inspected.stage.unwrap();
	assert_eq!(native_identity(observed_stage.identity()).unwrap(), stage);
	assert_eq!(observed_stage.length(), 0);
	assert!(matches!(
		inspect_job_with_stage_read_back(&recovery, authority, &mut [0; 8]),
		Err(DarwinInspectionError::StageReadBack(
			DarwinStageReadBackError::MissingVerification
		))
	));
	assert_eq!(
		inspected.target.unwrap().length(),
		u64::try_from(incumbent.len()).unwrap()
	);

	assert!(matches!(
		inspect_job(
			&recovery,
			DarwinInspectionAuthority {
				destination_root: root_id([11; 16]),
				..authority
			}
		),
		Err(DarwinInspectionError::PlanBinding)
	));
	assert!(matches!(
		inspect_job(
			&recovery,
			DarwinInspectionAuthority {
				key: &SigningKey::from_bytes(&[5; 32]).verifying_key(),
				..authority
			}
		),
		Err(DarwinInspectionError::Replay(_))
	));
	assert_eq!(fs::read(path.join(FIRST_SEGMENT)).unwrap(), journal_before);
	assert_eq!(fs::read(fixture.0.join(TARGET)).unwrap(), incumbent);
}

const STAGED_PAYLOAD: &str = "stage/payload";

#[test]
fn retained_stage_read_back_refuses_invalid_scratch_extent_and_identity() {
	with_verified_stage(|job, authority, stage| {
		assert!(matches!(
			inspect_job_with_stage_read_back(job, authority, &mut []),
			Err(DarwinInspectionError::StageReadBack(
				DarwinStageReadBackError::Input(_)
			))
		));
		let mut large = vec![0; MAX_STAGE_IO_BYTES + 1];
		assert!(matches!(
			inspect_job_with_stage_read_back(job, authority, &mut large),
			Err(DarwinInspectionError::StageReadBack(
				DarwinStageReadBackError::ScratchTooLarge { length }
			)) if length == large.len()
		));

		let refuses_binding = || {
			assert!(matches!(
				inspect_job_with_stage_read_back(job, authority, &mut [0; 8]),
				Err(DarwinInspectionError::StageReadBack(
					DarwinStageReadBackError::StageBinding
				))
			));
		};
		fs::write(stage, &PAYLOAD[..PAYLOAD.len() - 1]).unwrap();
		refuses_binding();

		let retained = stage.with_extension("retained");
		fs::rename(stage, &retained).unwrap();
		fs::write(stage, PAYLOAD).unwrap();
		fs::set_permissions(stage, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
		refuses_binding();
		assert_eq!(fs::read(retained).unwrap(), &PAYLOAD[..PAYLOAD.len() - 1]);
	});
}

#[test]
fn retained_stage_read_back_refuses_a_visible_attribute_before_payload_io() {
	with_verified_stage(|job, authority, stage| {
		assert!(
			Command::new("/usr/bin/xattr")
				.args(["-w", "com.example.exacopy-recovery", "fixture"])
				.arg(stage)
				.status()
				.unwrap()
				.success()
		);
		let before = fs::metadata(stage).unwrap();
		assert!(matches!(
			inspect_job_with_stage_read_back(job, authority, &mut [0; 8]),
			Err(DarwinInspectionError::StageReadBack(
				DarwinStageReadBackError::Platform(RecoveryError::Managed(
					StageError::BasicMetadata(BasicMetadataError::ExtendedAttributes)
				))
			))
		));
		let after = fs::metadata(stage).unwrap();
		assert_eq!(
			(before.atime(), before.atime_nsec()),
			(after.atime(), after.atime_nsec())
		);
	});
}

#[test]
#[ignore = "requires a native APFS stage with zero visible xattrs"]
fn retained_stage_read_back_measures_live_bytes_and_refuses_same_inode_corruption() {
	with_verified_stage(|job, authority, stage| {
		let (inspected, digest) =
			inspect_job_with_stage_read_back(job, authority, &mut [0; 8]).unwrap();
		assert_eq!(inspected.replay.status(), DarwinReplayStatus::Incomplete);
		assert_eq!(digest.as_bytes(), blake3::hash(PAYLOAD).as_bytes());

		let mut changed = PAYLOAD.to_vec();
		changed[0] ^= 1;
		fs::write(stage, &changed).unwrap();
		assert!(matches!(
			inspect_job_with_stage_read_back(job, authority, &mut [0; 8]),
			Err(DarwinInspectionError::StageReadBack(
				DarwinStageReadBackError::DigestMismatch
			))
		));
		assert_eq!(fs::read(stage).unwrap(), changed);
	});
}

fn with_verified_stage(
	observe: impl FnOnce(&RecoveryJob<'_>, DarwinInspectionAuthority<'_>, &Path),
) {
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
		job.with_admitted_entry(|_| ()).unwrap();
	})
	.unwrap();
	let journal_path = path.join(FIRST_SEGMENT);
	let mut frames = FrameReader::new(File::open(&journal_path).unwrap(), ChainHead::start());
	assert_eq!(
		frames.next_frame().unwrap().unwrap().kind(),
		FrameKind::JobPrepared
	);
	let prepared = frames.next_frame().unwrap().unwrap();
	assert!(frames.next_frame().unwrap().is_none());
	drop(frames);
	let stage_path = path.join(STAGED_PAYLOAD);
	fs::write(&stage_path, PAYLOAD).unwrap();
	// Synthetic history exercises replay and observation without performing publication.
	let entry = DarwinEntryPrepared::from_frame(&prepared)
		.unwrap()
		.preparation();
	let length = StreamLength::new(entry.source.length()).unwrap();
	let stage = entry.stage.identity;
	let seal = DarwinStageSealed::new(&prepared, stage, length).unwrap();
	let digest = StreamDigest::from_bytes(*blake3::hash(PAYLOAD).as_bytes());
	let verification = DarwinVerificationRecorded::new(
		&prepared,
		&seal,
		DarwinStreamEvidence {
			identity: entry.source.identity(),
			length,
			digest,
		},
		DarwinStreamEvidence {
			identity: stage,
			length,
			digest,
		},
	)
	.unwrap();
	let journal = fs::OpenOptions::new()
		.append(true)
		.open(&journal_path)
		.unwrap();
	let mut writer = FrameWriter::new(journal, prepared.head());
	writer
		.append(FrameKind::StageSealed, &seal.encode())
		.unwrap();
	writer
		.append(FrameKind::VerificationRecorded, &verification.encode())
		.unwrap();
	drop(writer);
	let segment_before = fs::read(&journal_path).unwrap();
	let target_path = fixture.0.join(TARGET);
	let incumbent = b"existing public contents";
	fs::write(&target_path, incumbent).unwrap();
	let target_before = fs::metadata(&target_path).unwrap();
	let recovery = container.open_recovery_job(name).unwrap();
	let authority = DarwinInspectionAuthority {
		profile: request.profile.id,
		key: &signer.verifying_key(),
		destination_root: request.destination_root_id,
	};
	observe(&recovery, authority, &stage_path);
	let target_after = fs::metadata(&target_path).unwrap();
	assert_eq!(
		(target_before.atime(), target_before.atime_nsec()),
		(target_after.atime(), target_after.atime_nsec())
	);
	assert_eq!(fs::read(&target_path).unwrap(), incumbent);
	assert_eq!(fs::read(&journal_path).unwrap(), segment_before);
}
