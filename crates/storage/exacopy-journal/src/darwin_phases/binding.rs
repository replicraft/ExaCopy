use minicbor::Decoder;

use super::DarwinPhaseError;
use super::codec::{PayloadEncoder, PayloadWriteError};
use crate::frame::FrameKind;
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{DarwinEntryPrepared, DarwinStageId, JournalContext, JournalEntryId, OwnerDigest};

const PHASE_DIGEST_DOMAIN: &[u8] = b"ExaCopy/journal-darwin-phase/v2\0";

/// Job, plan, epoch, entry, signed owner, and model stage token for one phase observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinPhaseBinding {
	/// The job, epoch and plan.
	pub context: JournalContext,
	/// The exact journal entry ID.
	pub entry: JournalEntryId,
	/// The digest of the exact signed owner record.
	pub owner_digest: OwnerDigest,
	/// The adapter's opaque token for this model stage.
	pub stage_id: DarwinStageId,
}

impl DarwinPhaseBinding {
	pub(super) fn prepared(prepared: &DarwinEntryPrepared<'_>) -> Self {
		Self {
			context: prepared.context(),
			entry: prepared.entry(),
			owner_digest: prepared.owner_digest(),
			stage_id: prepared.preparation().stage.id,
		}
	}

	pub(super) fn write(self, encoder: &mut PayloadEncoder) -> Result<(), PayloadWriteError> {
		encoder
			.map(2)?
			.u8(0)?
			.bytes(self.owner_digest.as_bytes())?
			.u8(1)?
			.bytes(self.stage_id.as_bytes())?;
		Ok(())
	}

	pub(super) fn read(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, DarwinPhaseError> {
		expect_map(decoder, 2)?;
		expect_key(decoder, 0)?;
		let owner_digest = OwnerDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 1)?;
		let stage_id = DarwinStageId::from_bytes(read_fixed(decoder)?);
		Ok(Self {
			context,
			entry,
			owner_digest,
			stage_id,
		})
	}
}

/// A BLAKE3 digest of the phase domain, little-endian frame kind and canonical phase payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DarwinPhaseDigest([u8; 32]);

impl DarwinPhaseDigest {
	/// Wraps the digest of an observed phase.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Borrows the digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	pub(super) fn of(kind: FrameKind, payload: &[u8]) -> Self {
		Self::from_bytes(
			*blake3::Hasher::new()
				.update(PHASE_DIGEST_DOMAIN)
				.update(&kind.code().to_le_bytes())
				.update(payload)
				.finalize()
				.as_bytes(),
		)
	}
}
