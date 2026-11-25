use exacopy_journal::frame::{ChainHead, Frame, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinFileIdentity, DarwinNamespaceObservation as Name,
	DarwinPhaseError, DarwinPublicationBarriers, DarwinPublicationNames,
	DarwinPublicationOutcome as Outcome, DarwinPublishIntent, DarwinPublishObserved,
	DarwinReceiptCommitted, DarwinReceiptDigest, DarwinVolumeIdentity, DurabilityRecorded,
	PublishObserved, ReceiptCommitted,
};

use super::fixture::{Fixture, PUBLIC_NAME, frame, native};

const DIGEST: DarwinReceiptDigest = DarwinReceiptDigest::from_bytes([0x7a; 32]);

struct Records {
	metadata: Frame,
	intent: Frame,
	stage: DarwinFileIdentity,
	barriers: DarwinPublicationBarriers,
}

impl Records {
	fn new() -> Self {
		let fixture = Fixture::new(8192, PUBLIC_NAME);
		let seal = fixture.seal();
		let verification = fixture.verify(&seal);
		let metadata = fixture.metadata(&seal, &verification);
		let intent = fixture.intent(&seal, &verification, &metadata);
		let sealed = frame(FrameKind::StageSealed, &seal.encode(), fixture.frame.head());
		let verified = frame(
			FrameKind::VerificationRecorded,
			&verification.encode(),
			sealed.head(),
		);
		let metadata = frame(
			FrameKind::MetadataRecorded,
			&metadata.encode(),
			verified.head(),
		);
		let intent = frame(FrameKind::PublishIntent, &intent.encode(), metadata.head());
		Self {
			metadata,
			intent,
			stage: fixture.stage.identity,
			barriers: DarwinPublicationBarriers {
				stage_directory: fixture.stage.directory,
				destination_directory: fixture.parent,
			},
		}
	}

	fn published_names(&self) -> DarwinPublicationNames {
		DarwinPublicationNames {
			target: Name::Present(self.stage),
			stage: Name::Absent,
		}
	}

	fn observed(&self, outcome: Outcome, names: DarwinPublicationNames) -> Frame {
		let observed = DarwinPublishObserved::new(&self.intent, outcome, names).unwrap();
		frame(
			FrameKind::PublishObserved,
			&observed.encode(),
			self.intent.head(),
		)
	}

	fn barrier_frame(&self, observed: &Frame) -> Frame {
		let durability =
			DarwinDurabilityRecorded::new(&self.metadata, &self.intent, observed, self.barriers)
				.unwrap();
		frame(
			FrameKind::DurabilityRecorded,
			&durability.encode(),
			observed.head(),
		)
	}
}

#[test]
fn successful_observation_barriers_and_receipt_bind_exact_effect() {
	let records = Records::new();
	let observed = records.observed(Outcome::Published, records.published_names());
	let durability = records.barrier_frame(&observed);
	let commitment = DarwinReceiptCommitted::new(&durability, DIGEST).unwrap();
	let receipt = frame(
		FrameKind::ReceiptCommitted,
		&commitment.encode(),
		durability.head(),
	);

	let checked_observed = DarwinPublishObserved::from_frame(&observed).unwrap();
	let checked_barriers = DarwinDurabilityRecorded::from_frame(&durability).unwrap();
	let checked_receipt = DarwinReceiptCommitted::from_frame(&receipt).unwrap();
	let intent = DarwinPublishIntent::from_frame(&records.intent).unwrap();

	checked_observed.validate_intent(&records.intent).unwrap();
	checked_barriers
		.validate_evidence(&records.metadata, &records.intent, &observed)
		.unwrap();
	checked_receipt
		.validate_evidence(&durability, DIGEST)
		.unwrap();

	assert_eq!(checked_observed.published_target(), Some(records.stage));
	assert_eq!(checked_observed.intent(), records.intent.head());
	assert_eq!(checked_barriers.intent(), records.intent.head());
	assert_eq!(checked_barriers.observed(), observed.head());
	assert_eq!(checked_barriers.metadata(), records.metadata.head());
	assert_eq!(checked_barriers.barriers(), records.barriers);
	assert_eq!(checked_receipt, commitment);
	assert_eq!(checked_receipt.intent(), records.intent.head());
	assert_eq!(checked_receipt.durability(), durability.head());
	assert_eq!(checked_receipt.digest(), DIGEST);
	assert_eq!(checked_observed.binding(), intent.binding());
	assert_eq!(checked_barriers.binding(), intent.binding());
	assert_eq!(checked_receipt.binding(), intent.binding());
	assert_eq!(checked_observed.effect_sequence(), intent.effect_sequence());
	assert_eq!(checked_barriers.effect_sequence(), intent.effect_sequence());
	assert_eq!(checked_receipt.effect_sequence(), intent.effect_sequence());

	assert!(PublishObserved::from_frame(&observed).is_err());
	assert!(DurabilityRecorded::from_frame(&durability).is_err());
	assert!(ReceiptCommitted::from_frame(&receipt).is_err());
}

#[test]
fn all_incomplete_reports_retain_name_evidence_without_authorizing_barriers() {
	let records = Records::new();
	let cases = [
		(
			Outcome::RejectedBeforeRename,
			DarwinPublicationNames {
				target: Name::Unobserved,
				stage: Name::Unobserved,
			},
		),
		(
			Outcome::Conflict,
			DarwinPublicationNames {
				target: Name::PresentUnidentified,
				stage: Name::Present(records.stage),
			},
		),
		(
			Outcome::UncertainRename,
			DarwinPublicationNames {
				target: Name::Present(native(999)),
				stage: Name::Absent,
			},
		),
		(
			Outcome::RenameConfirmedIncomplete,
			records.published_names(),
		),
	];
	for (outcome, names) in cases {
		let observed = records.observed(outcome, names);
		let decoded = DarwinPublishObserved::from_frame(&observed).unwrap();
		decoded.validate_intent(&records.intent).unwrap();
		assert_eq!(decoded.outcome(), outcome);
		assert_eq!(decoded.names(), names);
		assert_eq!(decoded.published_target(), None);
		assert_eq!(
			DarwinDurabilityRecorded::new(
				&records.metadata,
				&records.intent,
				&observed,
				records.barriers,
			),
			Err(DarwinPhaseError::InconsistentObservation),
		);
	}
	let fresh = records.observed(Outcome::ReconciledPublished, records.published_names());
	assert_eq!(
		DarwinPublishObserved::from_frame(&fresh).unwrap().outcome(),
		Outcome::ReconciledPublished,
	);
	assert!(DarwinDurabilityRecorded::from_frame(&records.barrier_frame(&fresh)).is_ok());
}

#[test]
fn success_requires_current_stage_identity_and_absent_old_name() {
	let records = Records::new();
	let altered_generation = DarwinFileIdentity::new(
		records.stage.volume(),
		records.stage.inode(),
		None,
		records.stage.birth(),
	);
	for outcome in [Outcome::Published, Outcome::ReconciledPublished] {
		for target in [Name::Absent, Name::Unobserved, Name::PresentUnidentified] {
			let names = DarwinPublicationNames {
				target,
				..records.published_names()
			};
			assert_eq!(
				DarwinPublishObserved::new(&records.intent, outcome, names),
				Err(DarwinPhaseError::InconsistentObservation),
			);
		}
		for stage in [
			Name::Present(records.stage),
			Name::Unobserved,
			Name::PresentUnidentified,
		] {
			let names = DarwinPublicationNames {
				stage,
				..records.published_names()
			};
			assert_eq!(
				DarwinPublishObserved::new(&records.intent, outcome, names),
				Err(DarwinPhaseError::InconsistentObservation),
			);
		}
		for wrong_target in [native(999), altered_generation] {
			let names = DarwinPublicationNames {
				target: Name::Present(wrong_target),
				..records.published_names()
			};
			assert_eq!(
				DarwinPublishObserved::new(&records.intent, outcome, names),
				Err(DarwinPhaseError::IdentityMismatch),
			);
		}
	}
}

#[test]
fn completed_barriers_require_two_distinct_matching_same_volume_directories() {
	let records = Records::new();
	let observed = records.observed(Outcome::Published, records.published_names());
	let aliased = DarwinFileIdentity::new(
		records.barriers.stage_directory.volume(),
		records.barriers.stage_directory.inode(),
		None,
		records.barriers.stage_directory.birth(),
	);
	let other_volume = DarwinFileIdentity::new(
		DarwinVolumeIdentity::new(-3, [1, 2]).unwrap(),
		records.barriers.destination_directory.inode(),
		records.barriers.destination_directory.generation(),
		records.barriers.destination_directory.birth(),
	);
	for (barriers, expected) in [
		(
			DarwinPublicationBarriers {
				stage_directory: records.barriers.destination_directory,
				destination_directory: records.barriers.stage_directory,
			},
			DarwinPhaseError::IdentityMismatch,
		),
		(
			DarwinPublicationBarriers {
				destination_directory: aliased,
				..records.barriers
			},
			DarwinPhaseError::AliasedIdentity,
		),
		(
			DarwinPublicationBarriers {
				destination_directory: other_volume,
				..records.barriers
			},
			DarwinPhaseError::VolumeMismatch,
		),
		(
			DarwinPublicationBarriers {
				stage_directory: native(999),
				..records.barriers
			},
			DarwinPhaseError::IdentityMismatch,
		),
	] {
		assert_eq!(
			DarwinDurabilityRecorded::new(&records.metadata, &records.intent, &observed, barriers),
			Err(expected),
		);
	}
}

#[test]
fn replay_requires_exact_references_even_when_payloads_match() {
	let records = Records::new();
	let observed = records.observed(Outcome::Published, records.published_names());
	let durability = records.barrier_frame(&observed);
	let committed = DarwinReceiptCommitted::new(&durability, DIGEST).unwrap();

	let foreign_anchor = |number| ChainHead::after(number, [0x62; 32]).unwrap();
	let other_intent = frame(
		FrameKind::PublishIntent,
		records.intent.payload(),
		foreign_anchor(records.metadata.head().sequence()),
	);
	assert_eq!(
		other_intent.head().sequence(),
		records.intent.head().sequence()
	);
	assert_eq!(
		DarwinPublishObserved::from_frame(&observed)
			.unwrap()
			.validate_intent(&other_intent),
		Err(DarwinPhaseError::BindingMismatch),
	);

	let other_observation = frame(
		FrameKind::PublishObserved,
		observed.payload(),
		foreign_anchor(records.intent.head().sequence()),
	);
	let checked_barriers = DarwinDurabilityRecorded::from_frame(&durability).unwrap();
	assert_eq!(
		checked_barriers.validate_evidence(&records.metadata, &records.intent, &other_observation),
		Err(DarwinPhaseError::BindingMismatch),
	);

	let other_barriers = frame(
		FrameKind::DurabilityRecorded,
		durability.payload(),
		foreign_anchor(observed.head().sequence()),
	);
	assert_eq!(
		committed.validate_evidence(&other_barriers, DIGEST),
		Err(DarwinPhaseError::BindingMismatch),
	);
	assert_eq!(
		committed.validate_evidence(&durability, DarwinReceiptDigest::from_bytes([0xff; 32])),
		Err(DarwinPhaseError::BindingMismatch),
	);
}

#[test]
fn barrier_construction_rejects_other_metadata_in_same_job_and_stage() {
	let records = Records::new();
	let observed = records.observed(Outcome::Published, records.published_names());
	let mut payload = records.metadata.payload().to_vec();
	// The verification digest is the 32-byte byte string in body key 1, directly
	// after the binding's stage token of sixteen 0x44 bytes.
	let start = payload
		.windows(19)
		.position(|window| window[..16] == [0x44; 16] && window[16..] == [1, 0x58, 32])
		.unwrap();
	payload[start + 19] ^= 1;
	let substituted_metadata = frame(
		FrameKind::MetadataRecorded,
		&payload,
		ChainHead::after(
			records.metadata.head().sequence() - 1,
			records.metadata.previous_digest(),
		)
		.unwrap(),
	);
	assert_eq!(
		DarwinDurabilityRecorded::new(
			&substituted_metadata,
			&records.intent,
			&observed,
			records.barriers,
		),
		Err(DarwinPhaseError::BindingMismatch),
	);
}

#[path = "publication_wire.rs"]
mod wire;
