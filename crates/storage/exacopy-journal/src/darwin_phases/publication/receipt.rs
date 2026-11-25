use core::num::NonZeroU64;

use minicbor::Decoder;

use super::DarwinDurabilityRecorded;
use super::binding::{ActiveIntent, read_reference, require_before, write_reference};
use crate::LOCAL_RECEIPT_LOCATION;
use crate::darwin_phases::codec::{decode_record, encode_record, expect_code, frame_payload};
use crate::darwin_phases::{DarwinPhaseBinding, DarwinPhaseError};
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};

const KIND: FrameKind = FrameKind::ReceiptCommitted;
const RECEIPT_SUCCESS: u64 = 1;
const JOURNAL_RETENTION_ROOT: u64 = 1;

/// Digest of the exact canonical managed APFS copy receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DarwinReceiptDigest([u8; 32]);

impl DarwinReceiptDigest {
	/// Wraps the digest calculated over a managed APFS receipt by the artifact codec.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Borrows the exact digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Kind 18 commits an exact managed APFS receipt and retains its publication evidence.
///
/// The coordinator independently checks the receipt's association and publishes it under the
/// verified private job directory before appending this record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinReceiptCommitted {
	active: ActiveIntent,
	durability: ChainHead,
	digest: DarwinReceiptDigest,
}

impl DarwinReceiptCommitted {
	/// Constructs a commitment for a published receipt after its required barriers complete.
	/// # Errors
	/// Rejects an invalid kind-9 frame.
	pub fn new(
		durability_frame: &Frame,
		digest: DarwinReceiptDigest,
	) -> Result<Self, DarwinPhaseError> {
		let durability = DarwinDurabilityRecorded::from_frame(durability_frame)?;
		Ok(Self {
			active: durability.active(),
			durability: durability_frame.head(),
			digest,
		})
	}

	/// Returns the signed-owner and model-stage association.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.active.binding
	}

	/// Returns the sequence of the active effect.
	#[must_use]
	pub const fn effect_sequence(&self) -> NonZeroU64 {
		self.active.effect
	}

	/// Returns the exact kind-7 frame reference.
	#[must_use]
	pub const fn intent(&self) -> ChainHead {
		self.active.reference
	}

	/// Returns the exact retaining kind-9 frame reference.
	#[must_use]
	pub const fn durability(&self) -> ChainHead {
		self.durability
	}

	/// Returns the committed receipt digest.
	#[must_use]
	pub const fn digest(&self) -> DarwinReceiptDigest {
		self.digest
	}

	/// Encodes the kind-18 managed APFS payload using deterministic CBOR.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			self.active.write_header(encoder)?;
			encoder
				.map(4)?
				.u8(0)?
				.bytes(self.digest.as_bytes())?
				.u8(1)?
				.str(LOCAL_RECEIPT_LOCATION)?
				.u8(2)?
				.u64(RECEIPT_SUCCESS)?
				.u8(3)?
				.array(1)?
				.map(3)?
				.u8(0)?
				.u64(JOURNAL_RETENTION_ROOT)?
				.u8(1)?;
			write_reference(encoder, self.durability)?;
			encoder.u8(2)?;
			self.active.write(encoder)
		})
	}

	/// Decodes one complete canonical managed APFS kind-18 payload.
	/// # Errors
	/// Rejects malformed or incompatible commitment evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Decodes a kind-18 frame and checks that its references precede it.
	/// # Errors
	/// Rejects a wrong kind, invalid payload or out-of-order evidence.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		let record = Self::decode(frame_payload(frame, KIND)?)?;
		require_before(record.durability(), frame.head())?;
		Ok(record)
	}

	/// Validates the exact barrier frame and independently computed receipt digest.
	///
	/// The caller validates the chain and the decoded receipt's association with the
	/// job and the completed publication. A digest alone conveys no filesystem authority.
	/// # Errors
	/// Rejects an invalid barrier frame, a mismatched effect or a different receipt digest.
	pub fn validate_evidence(
		&self,
		durability_frame: &Frame,
		observed_digest: DarwinReceiptDigest,
	) -> Result<(), DarwinPhaseError> {
		if *self != Self::new(durability_frame, observed_digest)? {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		Ok(())
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let header = ActiveIntent::read_header(decoder)?;
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let digest = DarwinReceiptDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 1)?;
		if decoder.str()? != LOCAL_RECEIPT_LOCATION {
			return Err(DarwinPhaseError::UnsupportedEvidence);
		}
		expect_key(decoder, 2)?;
		expect_code(decoder, RECEIPT_SUCCESS)?;
		expect_key(decoder, 3)?;
		if decoder.array()? != Some(1) {
			return Err(DarwinPhaseError::UnsupportedEvidence);
		}
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		expect_code(decoder, JOURNAL_RETENTION_ROOT)?;
		expect_key(decoder, 1)?;
		let durability = read_reference(decoder)?;
		expect_key(decoder, 2)?;
		let active = ActiveIntent::read(decoder, header)?;
		require_before(active.reference, durability)?;
		Ok(Self {
			active,
			durability,
			digest,
		})
	}
}
