use core::num::NonZeroU64;

use minicbor::Decoder;

use super::codec::{
	decode_frame, decode_record, encode_record, read_reference, require_before,
	require_predecessor, require_reference, write_reference,
};
use super::{RecoveryDecisionFrames, RecoveryDirectories, RecoveryRecordError, RecoveryStarted};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_identity, write_identity};
use crate::{
	JournalContext, JournalEntryId, LinuxFileIdentity, MetadataRecorded, OwnerDigest,
	VerificationRecorded,
};

const RETRY_RETAINED_PUBLICATION: u64 = 2;
const PUBLIC_TARGET_ABSENT: u64 = 0;
const PRIVATE_STAGE_PRESENT: u64 = 1;

/// Exact observations and fresh frame references for retained-stage publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedPublicationEvidence {
	/// Original file identity found at its private stage name.
	pub stage: LinuxFileIdentity,
	/// Held private stage directory and destination directory with an absent target.
	pub directories: RecoveryDirectories,
	/// Fresh kind-5 source measurement and stage read-back.
	pub verification: ChainHead,
	/// Fresh kind-6 required metadata and file barrier.
	pub metadata: ChainHead,
}

/// A local kind-20 record that binds fresh retained-stage evidence to a new effect sequence.
///
/// A subsequent kind-7 intent and live admission checks are required for publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedPublicationDecision {
	context: JournalContext,
	entry: JournalEntryId,
	started: ChainHead,
	evidence: RetainedPublicationEvidence,
	effect_sequence: NonZeroU64,
}

impl RetainedPublicationDecision {
	/// Constructs a retained-stage retry decision for the next publication effect.
	///
	/// # Errors
	/// Rejects a zero effect sequence, invalid identity scope, or invalid evidence order.
	pub fn new(
		context: JournalContext,
		entry: JournalEntryId,
		started: ChainHead,
		evidence: RetainedPublicationEvidence,
		effect_sequence: u64,
	) -> Result<Self, RecoveryRecordError> {
		let effect_sequence =
			NonZeroU64::new(effect_sequence).ok_or(RecoveryRecordError::InvalidEffectSequence)?;
		require_reference(started)?;
		require_reference(evidence.verification)?;
		require_reference(evidence.metadata)?;
		if started.sequence().checked_add(1) != Some(evidence.verification.sequence())
			|| evidence.verification.sequence().checked_add(1) != Some(evidence.metadata.sequence())
		{
			return Err(RecoveryRecordError::InvalidFrameOrder);
		}
		let directories = evidence.directories;
		if evidence.stage == directories.stage
			|| evidence.stage == directories.destination
			|| directories.stage == directories.destination
			|| directories.stage.device() != directories.destination.device()
			|| evidence.stage.device() != directories.destination.device()
		{
			return Err(RecoveryRecordError::InvalidIdentityScope);
		}
		Ok(Self {
			context,
			entry,
			started,
			evidence,
			effect_sequence,
		})
	}

	/// Returns the job, plan and generation that revalidated the stage.
	#[must_use]
	pub const fn context(&self) -> JournalContext {
		self.context
	}

	/// Returns the entry being reconciled.
	#[must_use]
	pub const fn entry(&self) -> JournalEntryId {
		self.entry
	}

	/// Returns the exact kind-19 recovery start that precedes the fresh evidence.
	#[must_use]
	pub const fn started(&self) -> ChainHead {
		self.started
	}

	/// Returns the observed stage and directories and the fresh evidence references.
	#[must_use]
	pub const fn evidence(&self) -> RetainedPublicationEvidence {
		self.evidence
	}

	/// Returns the effect sequence reserved for a subsequent kind-7 intent.
	#[must_use]
	pub const fn effect_sequence(&self) -> u64 {
		self.effect_sequence.get()
	}

	/// Encodes the complete local v1 deterministic CBOR payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder
				.map(4)?
				.u8(0)?
				.u64(RETRY_RETAINED_PUBLICATION)?
				.u8(1)?
				.map(5)?
				.u8(0)?;
			write_identity(encoder, self.evidence.stage)?;
			encoder.u8(1)?;
			write_identity(encoder, self.evidence.directories.destination)?;
			encoder.u8(2)?;
			write_identity(encoder, self.evidence.directories.stage)?;
			encoder
				.u8(3)?
				.u64(PUBLIC_TARGET_ABSENT)?
				.u8(4)?
				.u64(PRIVATE_STAGE_PRESENT)?
				.u8(2)?
				.map(3)?
				.u8(0)?;
			write_reference(encoder, self.started)?;
			encoder.u8(1)?;
			write_reference(encoder, self.evidence.verification)?;
			encoder.u8(2)?;
			write_reference(encoder, self.evidence.metadata)?;
			encoder.u8(3)?.u64(self.effect_sequence.get())?;
			Ok(())
		})
	}

	/// Decodes a complete canonical payload for a retained-stage kind-20 record.
	///
	/// # Errors
	/// Rejects malformed, unsupported or inconsistent evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, RecoveryRecordError> {
		decode_record(payload, Self::read_body, Self::encode)
	}

	/// Checks the envelope kind and the exact kind-6 predecessor reference.
	///
	/// # Errors
	/// Rejects a wrong kind, invalid payload or mismatched preceding frame reference.
	pub fn from_frame(frame: &Frame) -> Result<Self, RecoveryRecordError> {
		decode_frame(frame, FrameKind::RecoveryDecision, Self::decode, |record| {
			record.evidence.metadata
		})
	}

	/// Checks the decision against verified chain frames and independently trusted bindings.
	///
	/// Supply the latest prior intent, the registered source identity, the trusted owner digest,
	/// the inspected directory identities, and the latest allocated effect sequence, including
	/// reservations without a later intent. The caller checks current namespace state, frame
	/// synchronization and agreement with the original stream measurements and metadata.
	///
	/// # Errors
	/// Rejects invalid or substituted evidence, mismatched context, or a skipped effect sequence.
	pub fn validate_evidence(
		&self,
		frames: RecoveryDecisionFrames<'_>,
		expected_owner: OwnerDigest,
		directories: RecoveryDirectories,
		expected_source: LinuxFileIdentity,
		last_allocated_effect_sequence: u64,
	) -> Result<(), RecoveryRecordError> {
		if self.started != frames.started.head()
			|| self.evidence.verification != frames.verification.head()
			|| self.evidence.metadata != frames.metadata.head()
			|| self.evidence.directories != directories
		{
			return Err(RecoveryRecordError::BindingMismatch);
		}
		require_before(frames.intent.head(), self.started)?;
		require_predecessor(self.started, frames.verification)?;
		require_predecessor(self.evidence.verification, frames.metadata)?;
		let started = RecoveryStarted::from_frame(frames.started)?;
		let intent = started.validate_intent(frames.intent, expected_owner)?;
		let verification = VerificationRecorded::from_frame(frames.verification)
			.map_err(RecoveryRecordError::Verification)?;
		let metadata = MetadataRecorded::from_frame(frames.metadata)
			.map_err(RecoveryRecordError::Verification)?;
		if started.context() != self.context
			|| started.entry() != self.entry
			|| verification.context != self.context
			|| metadata.context != self.context
			|| verification.entry != self.entry
			|| metadata.entry != self.entry
			|| verification.source().identity != expected_source
			|| verification.stage().identity != self.evidence.stage
			|| metadata.stage != self.evidence.stage
			|| intent.target.stage != self.evidence.stage
			|| intent.target.parent != directories.destination
		{
			return Err(RecoveryRecordError::BindingMismatch);
		}
		if intent.context.effect_sequence == 0
			|| last_allocated_effect_sequence < intent.context.effect_sequence
			|| last_allocated_effect_sequence.checked_add(1) != Some(self.effect_sequence.get())
		{
			return Err(RecoveryRecordError::InvalidEffectSequence);
		}
		Ok(())
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, RecoveryRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		if decoder.u64()? != RETRY_RETAINED_PUBLICATION {
			return Err(RecoveryRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 1)?;
		expect_map(decoder, 5)?;
		expect_key(decoder, 0)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 1)?;
		let destination_directory = read_identity(decoder)?;
		expect_key(decoder, 2)?;
		let stage_directory = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		if decoder.u64()? != PUBLIC_TARGET_ABSENT {
			return Err(RecoveryRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 4)?;
		if decoder.u64()? != PRIVATE_STAGE_PRESENT {
			return Err(RecoveryRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 2)?;
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		let started = read_reference(decoder)?;
		expect_key(decoder, 1)?;
		let verification = read_reference(decoder)?;
		expect_key(decoder, 2)?;
		let metadata = read_reference(decoder)?;
		expect_key(decoder, 3)?;
		let effect_sequence = decoder.u64()?;
		Self::new(
			context,
			entry,
			started,
			RetainedPublicationEvidence {
				stage,
				directories: RecoveryDirectories {
					stage: stage_directory,
					destination: destination_directory,
				},
				verification,
				metadata,
			},
			effect_sequence,
		)
	}
}
