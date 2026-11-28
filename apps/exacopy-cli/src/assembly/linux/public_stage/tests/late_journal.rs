use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};

use exacopy_journal::DurableJournalError;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameProblem, FrameReadError, FrameReader};
use exacopy_platform::linux::StageError;
use exacopy_transfer::linux::{
	CopyProfile, PublicApplyIntentObservation, PublicApplyIntentPreparationError,
	PublicApplyIntentSelection, PublicApplyStageRequest, stage_public_apply_and_propose_intent,
};
use rustix::fs::OFlags;

use super::{
	CopyRoots, Fixture, SOURCE, TARGET, attempt, component, fixture, fixture_qualification,
	plan_new_file,
};

const MAX_CONTROL_JOURNAL_BYTES: u64 = 16 * 1024;

struct FaultEvidence {
	journal: (u64, u64),
	stage: (u64, u64),
	faulted_bytes: Vec<u8>,
}

pub(super) fn assert_late_readback_refusal(
	fixture: &Fixture,
	roots: CopyRoots<'_>,
	request: &PublicApplyStageRequest<'_, '_, '_>,
	scratch: &mut [u8],
) {
	let attempt = attempt("late-journal-fault", 5);
	let private_plan = plan_new_file(roots, attempt, component(SOURCE), component(TARGET)).unwrap();
	let binding = Fixture::binding(request.approved, attempt);
	let request = PublicApplyStageRequest {
		private_plan: &private_plan,
		binding,
		profile: CopyProfile {
			owner_token: exacopy_journal::OwnerToken::from_bytes([11; 16]).unwrap(),
			..request.profile
		},
		..*request
	};
	let qualification = fixture_qualification(private_plan.source().root_identity.device());
	let observation = PublicApplyIntentObservation {
		now: request.profile.created,
		profile: qualification.profile,
		environment: qualification.environment,
	};
	let source = fixture.source();
	let source_id = regular_id(&fs::symlink_metadata(&source).unwrap());
	assert_eq!(fs::read(&source).unwrap(), fixture::APPROVED);
	let mut observations = 0;
	let mut fault = None;
	let result = stage_public_apply_and_propose_intent(
		roots,
		request,
		PublicApplyIntentSelection {
			approved_plan: binding.public_plan,
			qualification,
		},
		scratch,
		|_| {},
		|| {
			match observations {
				0 => assert!(!fixture.job(attempt).try_exists().unwrap()),
				1 => {
					let job = roots
						.destination
						.open_recovery_job(attempt.job_name)
						.unwrap();
					assert!(matches!(job.try_read_lease(), Err(StageError::JobBusy)));
					fault = Some(fault_early_frame(fixture, attempt));
				}
				_ => panic!("unexpected extra proposal observation"),
			}
			observations += 1;
			Some(observation)
		},
	);
	assert_eq!(observations, 2);
	assert!(
		matches!(
			result,
			Err(PublicApplyIntentPreparationError::SealReadback(
				DurableJournalError::ReadFrame(FrameReadError::Corrupt {
					offset: 0,
					problem: FrameProblem::Magic,
				})
			))
		),
		"unexpected result after corrupting the retained prefix: {result:?}"
	);

	let fault = fault.unwrap();
	let journal = OpenOptions::new()
		.read(true)
		.custom_flags(i32::try_from((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits()).unwrap())
		.open(fixture.journal(attempt))
		.unwrap();
	assert_eq!(regular_id(&journal.metadata().unwrap()), fault.journal);
	assert_eq!(read_journal(&journal), fault.faulted_bytes);
	let stage = fixture.stage(attempt);
	assert_eq!(
		regular_id(&fs::symlink_metadata(&stage).unwrap()),
		fault.stage
	);
	assert_eq!(fs::read(stage).unwrap(), fixture::APPROVED);
	assert_eq!(
		regular_id(&fs::symlink_metadata(&source).unwrap()),
		source_id
	);
	assert_eq!(fs::read(source).unwrap(), fixture::APPROVED);
	assert_eq!(
		fs::symlink_metadata(fixture.target()).unwrap_err().kind(),
		ErrorKind::NotFound
	);
}

fn fault_early_frame(
	fixture: &Fixture,
	attempt: exacopy_transfer::linux::PlanAttempt<'_>,
) -> FaultEvidence {
	let stage = fixture.stage(attempt);
	let stage_id = regular_id(&fs::symlink_metadata(&stage).unwrap());
	assert_eq!(fs::read(stage).unwrap(), fixture::APPROVED);
	let journal = OpenOptions::new()
		.read(true)
		.write(true)
		.custom_flags(i32::try_from((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits()).unwrap())
		.open(fixture.journal(attempt))
		.unwrap();
	let metadata = journal.metadata().unwrap();
	let journal_id = regular_id(&metadata);
	assert_eq!(metadata.nlink(), 1);
	let mut bytes = read_journal(&journal);
	let mut frames = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let first = frames.next_frame().unwrap().unwrap();
	assert_eq!(first.kind(), FrameKind::JobPrepared);
	let mut last = first.kind();
	while let Some(frame) = frames.next_frame().unwrap() {
		assert_ne!(frame.kind(), FrameKind::PublishIntent);
		last = frame.kind();
	}
	assert_eq!(last, FrameKind::MetadataRecorded);

	// Deliberately violate cooperative ownership in our disposable job. Change exactly
	// one early magic byte in place while all metadata frame bytes remain intact.
	bytes[0] ^= 1;
	journal.write_all_at(&bytes[..1], 0).unwrap();
	FaultEvidence {
		journal: journal_id,
		stage: stage_id,
		faulted_bytes: bytes,
	}
}

fn read_journal(file: &File) -> Vec<u8> {
	let mut bytes = Vec::new();
	file.take(MAX_CONTROL_JOURNAL_BYTES + 1)
		.read_to_end(&mut bytes)
		.unwrap();
	assert!(u64::try_from(bytes.len()).unwrap() <= MAX_CONTROL_JOURNAL_BYTES);
	bytes
}

fn regular_id(metadata: &Metadata) -> (u64, u64) {
	assert!(metadata.is_file());
	(metadata.dev(), metadata.ino())
}
