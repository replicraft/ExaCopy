use minicbor::Decoder;

use super::PublicationRecordError;
use super::codec::{
	PayloadEncoder, WriteError, Writer, decode_frame, decode_record, encode_record, encoded_bytes,
	read_reference, require_reference, write_reference,
};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_identity, write_identity};
use crate::{LinuxFileIdentity, PublishIntent, PublishIntentContext};

const OBSERVATION_UNOBSERVED: u64 = 0;
const OBSERVATION_ABSENT: u64 = 1;
const OBSERVATION_PRESENT: u64 = 2;

const OUTCOME_NOT_PERFORMED: u64 = 0;
const OUTCOME_PERFORMED: u64 = 1;
const OUTCOME_UNCERTAIN: u64 = 2;

/// An observation of one name relative to a bound directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceObservation {
	/// No trustworthy observation was available.
	Unobserved,
	/// The name was checked and absent.
	Absent,
	/// The name was observed with a native identity.
	Present(LinuxFileIdentity),
}

impl NamespaceObservation {
	fn write(self, encoder: &mut PayloadEncoder) -> Result<(), WriteError> {
		match self {
			Self::Unobserved => {
				encoder.array(1)?.u64(OBSERVATION_UNOBSERVED)?;
			}
			Self::Absent => {
				encoder.array(1)?.u64(OBSERVATION_ABSENT)?;
			}
			Self::Present(identity) => {
				encoder.array(2)?.u64(OBSERVATION_PRESENT)?;
				write_identity(encoder, identity)?;
			}
		}
		Ok(())
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationRecordError> {
		let fields = decoder.array()?;
		match (fields, decoder.u64()?) {
			(Some(1), OBSERVATION_UNOBSERVED) => Ok(Self::Unobserved),
			(Some(1), OBSERVATION_ABSENT) => Ok(Self::Absent),
			(Some(2), OBSERVATION_PRESENT) => Ok(Self::Present(read_identity(decoder)?)),
			_ => Err(PublicationRecordError::UnsupportedEvidence),
		}
	}
}

/// The caller's classification of an exclusive rename attempt and its namespace evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
	/// The target was observed with the intended stage identity and the original name was absent.
	Published {
		/// The identity at the target name.
		target: LinuxFileIdentity,
	},
	/// The original stage was observed in place and the intended file was not published.
	NotPerformed {
		/// The observed target identity, or none if the target was checked and absent.
		target: Option<LinuxFileIdentity>,
		/// The identity observed at the original stage name.
		stage: LinuxFileIdentity,
	},
	/// The observations require reconciliation before any further namespace effect.
	Uncertain {
		/// The available observation of the target name.
		target: NamespaceObservation,
		/// The available observation of the original stage name.
		stage_name: NamespaceObservation,
	},
}

impl PublicationOutcome {
	fn write(self, encoder: &mut PayloadEncoder) -> Result<(), WriteError> {
		let (target, stage_name, outcome) = match self {
			Self::Published { target } => (
				NamespaceObservation::Present(target),
				NamespaceObservation::Absent,
				OUTCOME_PERFORMED,
			),
			Self::NotPerformed { target, stage } => (
				target.map_or(NamespaceObservation::Absent, NamespaceObservation::Present),
				NamespaceObservation::Present(stage),
				OUTCOME_NOT_PERFORMED,
			),
			Self::Uncertain { target, stage_name } => (target, stage_name, OUTCOME_UNCERTAIN),
		};
		encoder.u8(1)?;
		target.write(encoder)?;
		encoder.u8(2)?;
		stage_name.write(encoder)?;
		encoder.u8(3)?.u64(outcome)?;
		Ok(())
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, PublicationRecordError> {
		use NamespaceObservation::{Absent, Present};

		expect_key(decoder, 1)?;
		let target = NamespaceObservation::read(decoder)?;
		expect_key(decoder, 2)?;
		let stage_name = NamespaceObservation::read(decoder)?;
		expect_key(decoder, 3)?;
		let outcome = match (decoder.u64()?, target, stage_name) {
			(OUTCOME_PERFORMED, Present(target), Absent) => Self::Published { target },
			(OUTCOME_NOT_PERFORMED, Absent, Present(stage)) => Self::NotPerformed {
				target: None,
				stage,
			},
			(OUTCOME_NOT_PERFORMED, Present(target), Present(stage)) => Self::NotPerformed {
				target: Some(target),
				stage,
			},
			(OUTCOME_UNCERTAIN, target, stage_name) => Self::Uncertain { target, stage_name },
			(OUTCOME_PERFORMED | OUTCOME_NOT_PERFORMED, _, _) => {
				return Err(PublicationRecordError::InconsistentObservation);
			}
			_ => return Err(PublicationRecordError::UnsupportedEvidence),
		};
		Ok(outcome)
	}
}

/// A kind-8 observation bound to one exact local publication intent.
///
/// Replay must validate the journal's ownership and chain before relating this observation
/// to current held names. The record conveys no namespace barrier or recovery authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishObserved {
	context: PublishIntentContext,
	intent: ChainHead,
	outcome: PublicationOutcome,
}

impl PublishObserved {
	/// Constructs an observation referring to a noninitial intent frame.
	///
	/// # Errors
	///
	/// Rejects the initial chain anchor and a claimed no-effect result with aliased names.
	pub fn new(
		context: PublishIntentContext,
		intent: ChainHead,
		outcome: PublicationOutcome,
	) -> Result<Self, PublicationRecordError> {
		require_reference(intent)?;
		if let PublicationOutcome::NotPerformed {
			target: Some(target),
			stage,
		} = outcome
			&& target == stage
		{
			return Err(PublicationRecordError::InconsistentObservation);
		}
		Ok(Self {
			context,
			intent,
			outcome,
		})
	}

	/// Returns the same job, entry, epoch, effect sequence and plan digest as kind 7.
	#[must_use]
	pub const fn context(&self) -> PublishIntentContext {
		self.context
	}

	/// Returns the exact kind-7 frame reference.
	#[must_use]
	pub const fn intent(&self) -> ChainHead {
		self.intent
	}

	/// Returns the recorded classification and available namespace observations.
	#[must_use]
	pub const fn outcome(&self) -> PublicationOutcome {
		self.outcome
	}

	/// Encodes the local deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encoded_bytes(&self.encode_bounded()).to_vec()
	}

	/// Decodes a complete canonical kind-8 payload.
	///
	/// # Errors
	///
	/// Rejects malformed or unsupported observations.
	pub fn decode(payload: &[u8]) -> Result<Self, PublicationRecordError> {
		decode_record(payload, Self::read_body, Self::encode_bounded)
	}

	/// Decodes the frame and checks that the referenced intent precedes it.
	///
	/// # Errors
	///
	/// Rejects a wrong kind, malformed payload or out-of-order reference.
	pub fn from_frame(frame: &Frame) -> Result<Self, PublicationRecordError> {
		decode_frame(
			frame,
			FrameKind::PublishObserved,
			Self::decode,
			Self::intent,
		)
	}

	/// Checks the exact intent frame, context and any claimed terminal stage identity.
	///
	/// # Errors
	///
	/// Rejects wrong references, mismatched identities and incompatible intent payloads.
	pub fn validate_intent(&self, frame: &Frame) -> Result<(), PublicationRecordError> {
		self.bound_intent(frame).map(|_| ())
	}

	pub(super) fn bound_intent<'a>(
		&self,
		frame: &'a Frame,
	) -> Result<PublishIntent<'a>, PublicationRecordError> {
		if self.intent != frame.head() {
			return Err(PublicationRecordError::BindingMismatch);
		}
		let intent = PublishIntent::from_frame(frame).map_err(PublicationRecordError::Intent)?;
		if self.context != intent.context {
			return Err(PublicationRecordError::BindingMismatch);
		}
		match self.outcome {
			PublicationOutcome::Published { target } if target != intent.target.stage => {
				Err(PublicationRecordError::InconsistentObservation)
			}
			PublicationOutcome::NotPerformed { stage, .. } if stage != intent.target.stage => {
				Err(PublicationRecordError::InconsistentObservation)
			}
			_ => Ok(intent),
		}
	}

	fn encode_bounded(&self) -> Writer {
		encode_record(&self.context, |encoder| {
			encoder.map(4)?.u8(0)?;
			write_reference(encoder, self.intent)?;
			self.outcome.write(encoder)
		})
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: PublishIntentContext,
	) -> Result<Self, PublicationRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let intent = read_reference(decoder)?;
		let outcome = PublicationOutcome::read(decoder)?;
		Self::new(context, intent, outcome)
	}
}
