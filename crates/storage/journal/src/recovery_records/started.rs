use minicbor::Decoder;

use super::RecoveryRecordError;
use super::codec::{
	decode_frame, decode_record, encode_record, read_reference, require_reference, write_reference,
};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{JournalContext, JournalEntryId, JournalEpoch, OwnerDigest, PublishIntent};

/// The authenticated owner and exact journal boundary from which recovery starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryStartEvidence {
	/// Exact reference to the cited publication intent.
	pub intent: ChainHead,
	/// Last frame before starting this recovery generation.
	pub preceding: ChainHead,
	/// Digest of the authenticated owner envelope under which recovery runs.
	pub authorization: OwnerDigest,
}

/// A local kind-19 record starting a fresh reconciliation generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryStarted {
	context: JournalContext,
	entry: JournalEntryId,
	prior_epoch: JournalEpoch,
	evidence: RecoveryStartEvidence,
}

impl RecoveryStarted {
	/// Constructs a recovery record for the next generation after the preceding journal state.
	///
	/// # Errors
	/// Rejects a skipped, repeated or exhausted generation, reserved references, and a
	/// cited intent reference that disagrees with the preceding journal boundary.
	pub fn new(
		context: JournalContext,
		entry: JournalEntryId,
		prior_epoch: JournalEpoch,
		evidence: RecoveryStartEvidence,
	) -> Result<Self, RecoveryRecordError> {
		if prior_epoch.get().checked_add(1) != Some(context.epoch.get()) {
			return Err(RecoveryRecordError::InvalidEpoch);
		}
		require_reference(evidence.intent)?;
		require_reference(evidence.preceding)?;
		if evidence.intent != evidence.preceding
			&& evidence.intent.sequence() >= evidence.preceding.sequence()
		{
			return Err(RecoveryRecordError::InvalidFrameOrder);
		}
		Ok(Self {
			context,
			entry,
			prior_epoch,
			evidence,
		})
	}

	/// Returns the job, plan, and fresh recovery generation.
	#[must_use]
	pub const fn context(&self) -> JournalContext {
		self.context
	}

	/// Returns the entry under reconciliation.
	#[must_use]
	pub const fn entry(&self) -> JournalEntryId {
		self.entry
	}

	/// Returns the active generation before recovery started.
	#[must_use]
	pub const fn prior_epoch(&self) -> JournalEpoch {
		self.prior_epoch
	}

	/// Returns the exact cited intent, preceding head, and owner envelope digest.
	#[must_use]
	pub const fn evidence(&self) -> RecoveryStartEvidence {
		self.evidence
	}

	/// Encodes the complete local v1 deterministic CBOR payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder
				.map(3)?
				.u8(0)?
				.u64(self.prior_epoch.get())?
				.u8(1)?
				.map(2)?
				.u8(0)?;
			write_reference(encoder, self.evidence.intent)?;
			encoder.u8(1)?;
			write_reference(encoder, self.evidence.preceding)?;
			encoder
				.u8(2)?
				.bytes(self.evidence.authorization.as_bytes())?;
			Ok(())
		})
	}

	/// Decodes a complete canonical payload for an identified kind-19 record.
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

	/// Binds this recovery start to the cited intent frame and independently trusted owner.
	///
	/// Supply the intent from the verified local chain. The caller checks synchronization,
	/// current OS ownership, and the active generation against the preceding journal state.
	///
	/// # Errors
	/// Rejects a wrong kind, different job, entry, plan, owner, or an intent generation after the prior epoch.
	pub fn validate_intent<'a>(
		&self,
		intent_frame: &'a Frame,
		expected_owner: OwnerDigest,
	) -> Result<PublishIntent<'a>, RecoveryRecordError> {
		if intent_frame.head() != self.evidence.intent
			|| expected_owner != self.evidence.authorization
		{
			return Err(RecoveryRecordError::BindingMismatch);
		}
		let intent =
			PublishIntent::from_frame(intent_frame).map_err(RecoveryRecordError::Intent)?;
		if intent.context.job != self.context.job
			|| intent.context.entry != self.entry
			|| intent.context.plan_digest != self.context.plan_digest
		{
			return Err(RecoveryRecordError::BindingMismatch);
		}
		if intent.context.epoch.get() > self.prior_epoch.get() {
			return Err(RecoveryRecordError::InvalidEpoch);
		}
		Ok(intent)
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, RecoveryRecordError> {
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		let prior_epoch = JournalEpoch::new(decoder.u64()?);
		expect_key(decoder, 1)?;
		expect_map(decoder, 2)?;
		expect_key(decoder, 0)?;
		let intent = read_reference(decoder)?;
		expect_key(decoder, 1)?;
		let preceding = read_reference(decoder)?;
		expect_key(decoder, 2)?;
		let authorization = OwnerDigest::from_bytes(read_fixed(decoder)?);
		Self::new(
			context,
			entry,
			prior_epoch,
			RecoveryStartEvidence {
				intent,
				preceding,
				authorization,
			},
		)
	}
}
