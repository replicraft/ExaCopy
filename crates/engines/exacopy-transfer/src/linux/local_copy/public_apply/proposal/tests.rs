use std::cell::{Cell, RefCell};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::rc::Rc;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::JournalFileBarrier;
use exacopy_endpoint::linux_copy::{CopySourceObservation, InodeTimestamp};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{
	ApplyQualificationDigest, DurableJournal, LinuxFileIdentity, OwnerProfileId, OwnerToken,
	PlanDigest, StreamDigest, StreamEvidence, VerificationRecorded,
};

use crate::linux::CopyProfile;
use crate::public_plan::admit_single_file_plan;

use super::super::super::records::{EntryEvidence, SealError, SealEvidence};
use super::super::tests::{EXPECTED, bundle, local_plan, measured, selected_binding};
use super::{
	ApplyCrashProfile, ApplyProcessCrashEnvironment, ApplyQualification, ApprovedPublicPlanDigest,
	JournalSegment, OwnerDigest, OwnerTimestamp, PublicApplyIntent, PublicApplyIntentObservation,
	PublicApplyIntentPreparationError as Error, PublicApplyIntentSelection,
	PublicApplyStageRequest, check_current, check_selection, propose,
};

const OWNER: OwnerDigest = OwnerDigest::from_bytes([0x41; 32]);
const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(7, 11);
type ProposalResult = Result<(), Error<(), (), ()>>;

fn with_request(
	test: impl FnOnce(
		PublicApplyStageRequest<'_, '_, 'static>,
		PublicApplyIntentSelection,
		PublicApplyIntentObservation,
	),
) {
	let mut binding = selected_binding();
	let (body, page, expected) = bundle(binding);
	binding.public_plan = ApprovedPublicPlanDigest::from_bytes(body.digest());
	let approved = admit_single_file_plan(body.canonical_cbor(), &page, expected).unwrap();
	let private = local_plan(binding);
	let signer = SigningKey::from_bytes(&[6; 32]);
	let created = OwnerTimestamp::new(50, 7).unwrap();
	let profile = CopyProfile {
		id: OwnerProfileId::from_bytes([7; 16]).unwrap(),
		signer: &signer,
		created,
		owner_token: OwnerToken::from_bytes([8; 16]).unwrap(),
	};
	let qualification = ApplyQualification {
		record: ApplyQualificationDigest::from_bytes([0x39; 32]),
		profile: ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
		environment: ApplyProcessCrashEnvironment {
			boot_id: [2; 16],
			mount_namespace: 9,
			unique_mount: 12,
			device: 7,
		},
	};
	test(
		PublicApplyStageRequest {
			approved: &approved,
			private_plan: &private,
			binding,
			profile,
		},
		PublicApplyIntentSelection {
			approved_plan: binding.public_plan,
			qualification,
		},
		PublicApplyIntentObservation {
			now: created,
			profile: qualification.profile,
			environment: qualification.environment,
		},
	);
}

fn capture_seal(request: &PublicApplyStageRequest<'_, '_, '_>) -> SealEvidence {
	let plan = request.private_plan;
	let time = InodeTimestamp {
		seconds: 30,
		nanoseconds: 0,
	};
	EntryEvidence::new::<(), (), ()>(
		CopySourceObservation {
			mode: 0o600,
			owner: 1000,
			group: 1000,
			links: 1,
			accessed_at: time,
			modified_at: time,
			changed_at: time,
		},
		plan.source().file_identity,
		request.binding.stream_length.get(),
		plan.context(),
		plan.attempt().entry,
		plan.destination(),
	)
	.unwrap()
	.seal_stream(
		STAGE,
		request.binding.stream_length.get(),
		measured(EXPECTED),
	)
	.unwrap()
}

#[test]
fn proposal_binds_the_actual_synced_pair_without_appending_an_intent() {
	with_request(|request, selected, observed| {
		let seal = capture_seal(&request);
		let segment = Segment::default();
		let mut writer = DurableJournal::from_new_segment(segment.clone()).unwrap();
		let recorded = seal.record_with_heads(&mut writer).unwrap();
		let bytes = segment.snapshot();
		let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
		let stage_sealed = reader.next_frame().unwrap().unwrap();
		let verified = reader.next_frame().unwrap().unwrap();
		let metadata = reader.next_frame().unwrap().unwrap();
		assert_eq!(stage_sealed.kind(), FrameKind::StageSealed);
		assert_eq!(verified.kind(), FrameKind::VerificationRecorded);
		assert_eq!(metadata.kind(), FrameKind::MetadataRecorded);
		assert!(reader.next_frame().unwrap().is_none());

		let proposal =
			propose::<(), (), ()>(&request, selected, observed.now, OWNER, &recorded).unwrap();
		let association = proposal.association();
		assert_eq!(association.owner_digest, OWNER);
		assert_eq!(association.public_plan, request.binding.public_plan);
		assert_eq!(association.public_entry, request.binding.public_entry);
		assert_eq!(
			proposal.private().context.job,
			request.private_plan.attempt().job
		);
		assert_eq!(
			proposal.private().context.entry,
			request.binding.private_entry
		);
		assert_eq!(proposal.private().context.epoch, request.binding.epoch);
		assert_eq!(
			proposal.private().context.plan_digest,
			request.private_plan.digest()
		);
		assert_eq!(proposal.private().target.stage, STAGE);
		assert_eq!(
			proposal.private().target.verification_digest,
			seal.verification.record_digest()
		);
		assert_eq!(proposal.evidence().verification, verified.head());
		assert_eq!(proposal.evidence().metadata, metadata.head());
		assert_eq!(metadata.previous_digest(), verified.head().digest());
		assert_eq!(proposal.evidence().qualification, selected.qualification);
		assert_eq!(proposal.evidence().intent_time, observed.now);
		assert_eq!(
			PublicApplyIntent::decode(&proposal.encode()).unwrap(),
			proposal
		);
		assert_eq!(segment.snapshot(), bytes);

		let ordinary_segment = Segment::default();
		let mut writer = DurableJournal::from_new_segment(ordinary_segment.clone()).unwrap();
		assert_eq!(seal.record(&mut writer).unwrap().head(), metadata.head());
		assert_eq!(ordinary_segment.snapshot(), bytes);
	});
}

#[test]
fn selected_approval_and_qualification_are_checked_before_staging() {
	with_request(|request, selected, _| {
		let check = |selection| -> ProposalResult { check_selection(&request, selection) };
		assert!(check(selected).is_ok());
		assert!(matches!(
			check(PublicApplyIntentSelection {
				approved_plan: ApprovedPublicPlanDigest::from_bytes([9; 32]),
				..selected
			}),
			Err(Error::Approval)
		));
		let mut wrong = selected;
		wrong.qualification.record = ApplyQualificationDigest::from_bytes([0; 32]);
		assert!(matches!(check(wrong), Err(Error::Qualification)));
		wrong = selected;
		wrong.qualification.environment.device = 8;
		assert!(matches!(check(wrong), Err(Error::Qualification)));
	});
}

#[test]
fn current_observation_and_time_are_required_at_the_same_seal() {
	with_request(|request, selected, observed| {
		let offer = |current| {
			check_current::<(), (), ()>(&request, selected, current, request.profile.created)
		};
		assert!(matches!(offer(None), Err(Error::ObservationUnavailable)));
		let mut changed = observed;
		changed.environment.unique_mount += 1;
		assert!(matches!(offer(Some(changed)), Err(Error::Qualification)));
		for nanos in [6, 8] {
			let mut changed = observed;
			changed.now = OwnerTimestamp::new(50, nanos).unwrap();
			assert!(matches!(offer(Some(changed)), Err(Error::Time)));
		}
	});
}

#[test]
fn other_private_plan_and_changed_stream_cannot_propose() {
	with_request(|request, selected, observed| {
		for changed in [false, true] {
			let mut seal = capture_seal(&request);
			if changed {
				let digest = StreamDigest::from_bytes([8; 32]);
				seal.verification = VerificationRecorded::new(
					seal.verification.context,
					seal.verification.entry,
					StreamEvidence {
						digest,
						..seal.verification.source()
					},
					StreamEvidence {
						digest,
						..seal.verification.stage()
					},
				)
				.unwrap();
			} else {
				seal.verification.context.plan_digest = PlanDigest::from_bytes([8; 32]);
			}
			let mut writer = DurableJournal::from_new_segment(Segment::default()).unwrap();
			let recorded = seal.record_with_heads(&mut writer).unwrap();
			assert!(matches!(
				propose::<(), (), ()>(&request, selected, observed.now, OWNER, &recorded),
				Err(Error::SealBinding)
			));
		}
	});
}

#[test]
fn incomplete_seal_barrier_never_returns_the_recorded_pair() {
	with_request(|request, _, _| {
		let seal = capture_seal(&request);
		for (fails_after, expected) in [
			(1, FrameKind::VerificationRecorded),
			(2, FrameKind::MetadataRecorded),
		] {
			let segment = Segment::default();
			segment.sync_budget.set(Some(fails_after));
			let mut writer = DurableJournal::from_new_segment(segment).unwrap();
			assert!(matches!(
				seal.record_with_heads(&mut writer),
				Err(SealError::Journal { kind, .. }) if kind == expected
			));
		}
	});
}

#[derive(Clone, Default)]
struct Segment {
	cursor: Rc<RefCell<Cursor<Vec<u8>>>>,
	sync_budget: Rc<Cell<Option<usize>>>,
}

impl Segment {
	fn snapshot(&self) -> Vec<u8> {
		self.cursor.borrow().get_ref().clone()
	}
}

impl Read for Segment {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.cursor.borrow_mut().read(bytes)
	}
}

impl Seek for Segment {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.cursor.borrow_mut().seek(position)
	}
}

impl Write for Segment {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.cursor.borrow_mut().write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl JournalSegment for Segment {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		Ok(Some(
			u64::try_from(self.cursor.borrow().get_ref().len()).unwrap(),
		))
	}

	fn sync(&self) -> io::Result<()> {
		if let Some(remaining) = self.sync_budget.get() {
			let next = remaining
				.checked_sub(1)
				.ok_or_else(|| io::Error::other("fixture barrier failed"))?;
			self.sync_budget.set(Some(next));
		}
		Ok(())
	}
}
