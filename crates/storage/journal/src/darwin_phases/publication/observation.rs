use core::num::NonZeroU64;

use minicbor::Decoder;

use super::binding::{ActiveIntent, require_before};
use crate::DarwinFileIdentity;
use crate::darwin_phases::codec::{
	PayloadEncoder, PayloadWriteError, decode_record, encode_record, frame_payload,
};
use crate::darwin_phases::{DarwinPhaseBinding, DarwinPhaseError, DarwinPublishIntent};
use crate::darwin_prepared::wire::{read_identity, write_identity};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map};

const KIND: FrameKind = FrameKind::PublishObserved;

const UNOBSERVED: u64 = 0;
const ABSENT: u64 = 1;
const PRESENT: u64 = 2;
const PRESENT_UNIDENTIFIED: u64 = 3;

const REJECTED_BEFORE_RENAME: u64 = 0;
const CONFLICT: u64 = 1;
const UNCERTAIN_RENAME: u64 = 2;
const RENAME_CONFIRMED_INCOMPLETE: u64 = 3;
const PUBLISHED: u64 = 4;
const RECONCILED_PUBLISHED: u64 = 5;

/// A name observation under an independently validated directory capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DarwinNamespaceObservation {
	/// The name could not be checked reliably.
	Unobserved,
	/// A reliable lookup confirmed that the name was absent.
	Absent,
	/// A lookup established a native identity for the name.
	Present(DarwinFileIdentity),
	/// The name exists, but a native identity could not be established under this profile.
	PresentUnidentified,
}

impl DarwinNamespaceObservation {
	fn write(self, encoder: &mut PayloadEncoder) -> Result<(), PayloadWriteError> {
		match self {
			Self::Unobserved => {
				encoder.array(1)?.u64(UNOBSERVED)?;
			}
			Self::Absent => {
				encoder.array(1)?.u64(ABSENT)?;
			}
			Self::Present(identity) => {
				encoder.array(2)?.u64(PRESENT)?;
				write_identity(encoder, identity)?;
			}
			Self::PresentUnidentified => {
				encoder.array(1)?.u64(PRESENT_UNIDENTIFIED)?;
			}
		}
		Ok(())
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		match (decoder.array()?, decoder.u64()?) {
			(Some(1), UNOBSERVED) => Ok(Self::Unobserved),
			(Some(1), ABSENT) => Ok(Self::Absent),
			(Some(2), PRESENT) => Ok(Self::Present(read_identity(decoder)?)),
			(Some(1), PRESENT_UNIDENTIFIED) => Ok(Self::PresentUnidentified),
			_ => Err(DarwinPhaseError::UnsupportedEvidence),
		}
	}
}

/// The observed public and private names of one bound publication effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinPublicationNames {
	/// Observation of the exact public target component.
	pub target: DarwinNamespaceObservation,
	/// Observation of the original private stage name.
	pub stage: DarwinNamespaceObservation,
}

/// The executor's result or a later reconciliation of the same publication effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DarwinPublicationOutcome {
	/// The adapter stopped before calling exclusive rename.
	RejectedBeforeRename,
	/// Exclusive rename reported an incumbent.
	Conflict,
	/// The exclusive rename call returned an uncertain effect.
	UncertainRename,
	/// Exclusive rename reported success, but subsequent checks or barriers had an error.
	RenameConfirmedIncomplete,
	/// Exclusive rename reported success and the adapter reobserved the bound target.
	Published,
	/// Fresh reconciliation matched the target to the verified stage with the old name absent.
	ReconciledPublished,
}

impl DarwinPublicationOutcome {
	const fn code(self) -> u64 {
		match self {
			Self::RejectedBeforeRename => REJECTED_BEFORE_RENAME,
			Self::Conflict => CONFLICT,
			Self::UncertainRename => UNCERTAIN_RENAME,
			Self::RenameConfirmedIncomplete => RENAME_CONFIRMED_INCOMPLETE,
			Self::Published => PUBLISHED,
			Self::ReconciledPublished => RECONCILED_PUBLISHED,
		}
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		match decoder.u64()? {
			REJECTED_BEFORE_RENAME => Ok(Self::RejectedBeforeRename),
			CONFLICT => Ok(Self::Conflict),
			UNCERTAIN_RENAME => Ok(Self::UncertainRename),
			RENAME_CONFIRMED_INCOMPLETE => Ok(Self::RenameConfirmedIncomplete),
			PUBLISHED => Ok(Self::Published),
			RECONCILED_PUBLISHED => Ok(Self::ReconciledPublished),
			_ => Err(DarwinPhaseError::UnsupportedEvidence),
		}
	}
}

/// Kind 8 relates the executor's report and its namespace observations to an exact intent.
///
/// The caller checks journal ownership, chain membership and that this intent is the active
/// effect. Fresh observation and verification are still required when deciding recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinPublishObserved {
	active: ActiveIntent,
	outcome: DarwinPublicationOutcome,
	names: DarwinPublicationNames,
}

impl DarwinPublishObserved {
	/// Records available observations for a live attempt or a separate recovery decision.
	/// # Errors
	/// Rejects an invalid intent or a successful classification without matching names.
	pub fn new(
		intent_frame: &Frame,
		outcome: DarwinPublicationOutcome,
		names: DarwinPublicationNames,
	) -> Result<Self, DarwinPhaseError> {
		let intent = DarwinPublishIntent::from_frame(intent_frame)?;
		let record = Self::from_fields(ActiveIntent::new(intent_frame, intent), outcome, names)?;
		record.check_target(intent.target().stage)?;
		Ok(record)
	}

	/// Returns the exact frame reference of the active intent.
	#[must_use]
	pub const fn intent(&self) -> ChainHead {
		self.active.reference
	}

	/// Returns the job, entry, epoch, plan, owner and stage binding of the effect.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.active.binding
	}

	/// Returns the sequence of the active publication effect.
	#[must_use]
	pub const fn effect_sequence(&self) -> NonZeroU64 {
		self.active.effect
	}

	/// Returns the executor or reconciliation classification.
	#[must_use]
	pub const fn outcome(&self) -> DarwinPublicationOutcome {
		self.outcome
	}

	/// Returns the available namespace observations.
	#[must_use]
	pub const fn names(&self) -> DarwinPublicationNames {
		self.names
	}

	/// Returns the reobserved target for a successful classification.
	#[must_use]
	pub const fn published_target(&self) -> Option<DarwinFileIdentity> {
		match (self.outcome, self.names.target) {
			(
				DarwinPublicationOutcome::Published | DarwinPublicationOutcome::ReconciledPublished,
				DarwinNamespaceObservation::Present(target),
			) => Some(target),
			_ => None,
		}
	}

	/// Encodes the kind-8 managed APFS payload using deterministic CBOR.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			self.active.write_header(encoder)?;
			encoder.map(4)?.u8(0)?;
			self.active.write(encoder)?;
			encoder.u8(1)?;
			self.names.target.write(encoder)?;
			encoder.u8(2)?;
			self.names.stage.write(encoder)?;
			encoder.u8(3)?.u64(self.outcome.code())?;
			Ok(())
		})
	}

	/// Decodes one complete canonical managed APFS kind-8 payload.
	/// # Errors
	/// Rejects malformed, incompatible or contradictory payloads.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Decodes a kind-8 frame and checks that its intent reference precedes it.
	/// # Errors
	/// Rejects a wrong kind, invalid payload or out-of-order reference.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		let record = Self::decode(frame_payload(frame, KIND)?)?;
		require_before(record.intent(), frame.head())?;
		Ok(record)
	}

	/// Checks the exact active intent reference, effect association and any claimed success.
	/// # Errors
	/// Rejects different or incompatible intent evidence and wrong published identities.
	pub fn validate_intent(&self, frame: &Frame) -> Result<(), DarwinPhaseError> {
		self.bound_intent(frame).map(|_| ())
	}

	pub(super) fn bound_intent<'a>(
		&self,
		frame: &'a Frame,
	) -> Result<DarwinPublishIntent<'a>, DarwinPhaseError> {
		let intent = self.active.validate(frame)?;
		self.check_target(intent.target().stage)?;
		Ok(intent)
	}

	pub(super) const fn active(&self) -> ActiveIntent {
		self.active
	}

	fn check_target(&self, expected: DarwinFileIdentity) -> Result<(), DarwinPhaseError> {
		if let Some(target) = self.published_target()
			&& target != expected
		{
			return Err(DarwinPhaseError::IdentityMismatch);
		}
		Ok(())
	}

	fn from_fields(
		active: ActiveIntent,
		outcome: DarwinPublicationOutcome,
		names: DarwinPublicationNames,
	) -> Result<Self, DarwinPhaseError> {
		if matches!(
			outcome,
			DarwinPublicationOutcome::Published | DarwinPublicationOutcome::ReconciledPublished
		) && !matches!(
			names,
			DarwinPublicationNames {
				target: DarwinNamespaceObservation::Present(_),
				stage: DarwinNamespaceObservation::Absent,
			}
		) {
			return Err(DarwinPhaseError::InconsistentObservation);
		}
		Ok(Self {
			active,
			outcome,
			names,
		})
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let header = ActiveIntent::read_header(decoder)?;
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let active = ActiveIntent::read(decoder, header)?;
		expect_key(decoder, 1)?;
		let target = DarwinNamespaceObservation::read(decoder)?;
		expect_key(decoder, 2)?;
		let stage = DarwinNamespaceObservation::read(decoder)?;
		expect_key(decoder, 3)?;
		let outcome = DarwinPublicationOutcome::read(decoder)?;
		Self::from_fields(active, outcome, DarwinPublicationNames { target, stage })
	}
}
