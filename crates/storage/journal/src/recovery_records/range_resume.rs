use minicbor::Decoder;

use super::RecoveryRecordError;
use super::codec::{
	decode_frame, decode_record, encode_record, read_reference, require_reference, write_reference,
};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed, read_identity, write_identity};
use crate::{JournalContext, JournalEntryId, JournalEpoch, LinuxFileIdentity, OwnerDigest};

// JobPrepared occupies sequence one, before the original EntryPrepared.
const FIRST_ENTRY_SEQUENCE: u64 = 2;
const LOCAL_RANGE_RESUME_PROFILE: u64 = 1;

/// Authenticated owner, retained inode identities, and exact history for pre-intent resumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeResumeEvidence {
	/// Exact reference to the original entry preparation.
	pub preparation: ChainHead,
	/// Last frame before starting the new resume epoch.
	pub preceding: ChainHead,
	/// Original file identity observed at the retained private stage name.
	pub stage: LinuxFileIdentity,
	/// Identity of the held private directory containing the retained stage.
	pub stage_directory: LinuxFileIdentity,
	/// Digest of the independently authenticated owner envelope.
	pub authorization: OwnerDigest,
}

/// A local kind-19 record opening a fresh epoch for pre-intent range resumption.
///
/// Replay must bind the preparation to the verified history and check the active epoch,
/// owner, source observation, and destination root. The record alone grants no write
/// or publication authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeResumeStarted {
	context: JournalContext,
	entry: JournalEntryId,
	prior_epoch: JournalEpoch,
	evidence: RangeResumeEvidence,
}

impl RangeResumeStarted {
	/// Constructs a range resume record for the next journal epoch.
	///
	/// # Errors
	/// Rejects a skipped, repeated or exhausted epoch, invalid references or frame order,
	/// and stage identities that alias or reside on different devices.
	pub fn new(
		context: JournalContext,
		entry: JournalEntryId,
		prior_epoch: JournalEpoch,
		evidence: RangeResumeEvidence,
	) -> Result<Self, RecoveryRecordError> {
		if prior_epoch.get().checked_add(1) != Some(context.epoch.get()) {
			return Err(RecoveryRecordError::InvalidEpoch);
		}
		require_reference(evidence.preparation)?;
		require_reference(evidence.preceding)?;
		if evidence.preparation.sequence() < FIRST_ENTRY_SEQUENCE
			|| (evidence.preparation != evidence.preceding
				&& evidence.preparation.sequence() >= evidence.preceding.sequence())
		{
			return Err(RecoveryRecordError::InvalidFrameOrder);
		}
		if evidence.stage == evidence.stage_directory
			|| evidence.stage.device() != evidence.stage_directory.device()
		{
			return Err(RecoveryRecordError::InvalidIdentityScope);
		}
		Ok(Self {
			context,
			entry,
			prior_epoch,
			evidence,
		})
	}

	/// Returns the job, plan, and fresh resume epoch.
	#[must_use]
	pub const fn context(&self) -> JournalContext {
		self.context
	}

	/// Returns the entry to resume.
	#[must_use]
	pub const fn entry(&self) -> JournalEntryId {
		self.entry
	}

	/// Returns the active epoch before resumption started.
	#[must_use]
	pub const fn prior_epoch(&self) -> JournalEpoch {
		self.prior_epoch
	}

	/// Returns the retained stage identities, owner digest, and journal references.
	#[must_use]
	pub const fn evidence(&self) -> RangeResumeEvidence {
		self.evidence
	}

	/// Encodes the complete local v1 deterministic CBOR payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder
				.map(4)?
				.u8(0)?
				.u64(self.prior_epoch.get())?
				.u8(1)?
				.map(4)?
				.u8(0)?;
			write_reference(encoder, self.evidence.preparation)?;
			encoder.u8(1)?;
			write_reference(encoder, self.evidence.preceding)?;
			encoder.u8(2)?;
			write_identity(encoder, self.evidence.stage)?;
			encoder.u8(3)?;
			write_identity(encoder, self.evidence.stage_directory)?;
			encoder
				.u8(2)?
				.bytes(self.evidence.authorization.as_bytes())?
				.u8(3)?
				.u64(LOCAL_RANGE_RESUME_PROFILE)?;
			Ok(())
		})
	}

	/// Decodes a complete canonical pre-intent kind-19 payload.
	///
	/// # Errors
	/// Rejects malformed, unsupported or inconsistent evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, RecoveryRecordError> {
		decode_record(payload, Self::read_body, Self::encode)
	}

	/// Checks the envelope kind and its exact preceding sequence and digest.
	///
	/// # Errors
	/// Rejects a wrong kind, invalid payload or mismatched preceding frame reference.
	pub fn from_frame(frame: &Frame) -> Result<Self, RecoveryRecordError> {
		decode_frame(frame, FrameKind::RecoveryStarted, Self::decode, |record| {
			record.evidence.preceding
		})
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, RecoveryRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let prior_epoch = JournalEpoch::new(decoder.u64()?);
		expect_key(decoder, 1)?;
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let preparation = read_reference(decoder)?;
		expect_key(decoder, 1)?;
		let preceding = read_reference(decoder)?;
		expect_key(decoder, 2)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		let stage_directory = read_identity(decoder)?;
		expect_key(decoder, 2)?;
		let authorization = OwnerDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 3)?;
		if decoder.u64()? != LOCAL_RANGE_RESUME_PROFILE {
			return Err(RecoveryRecordError::UnsupportedEvidence);
		}
		Self::new(
			context,
			entry,
			prior_epoch,
			RangeResumeEvidence {
				preparation,
				preceding,
				stage,
				stage_directory,
				authorization,
			},
		)
	}
}
