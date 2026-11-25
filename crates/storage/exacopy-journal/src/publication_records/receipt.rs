use minicbor::Decoder;

use super::codec::{
	Writer, decode_frame, decode_record, encode_record, encoded_bytes, read_reference,
	require_reference, write_reference,
};
use super::{DurabilityRecorded, PublicationRecordError};
use crate::PublishIntentContext;
use crate::frame::{ChainHead, Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};

/// Local receipt path relative to the verified private job directory.
pub const LOCAL_RECEIPT_LOCATION: &str = "receipts/receipt.cbor";

const RECEIPT_SUCCESS: u64 = 1;
const JOURNAL_RETENTION_ROOT: u64 = 1;

/// Digest of a complete local Linux copy receipt under the receipt artifact's domain.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReceiptDigest([u8; 32]);

impl ReceiptDigest {
	/// Wraps the digest calculated over the canonical receipt artifact.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the exact 32 digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// A kind-18 record for one successfully published local Linux copy receipt.
///
/// The coordinator writes this record after the receipt's private file publication
/// and required barriers. It retains the verified journal history through the referenced
/// kind-9 frame. An artifact's own decoding, ownership and journal qualification remain
/// the replay caller's responsibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptCommitted {
	context: PublishIntentContext,
	digest: ReceiptDigest,
	durability: ChainHead,
}

impl ReceiptCommitted {
	/// Constructs a commitment to the exact receipt content and durability frame.
	///
	/// # Errors
	///
	/// Rejects the initial chain anchor.
	pub fn new(
		context: PublishIntentContext,
		digest: ReceiptDigest,
		durability: ChainHead,
	) -> Result<Self, PublicationRecordError> {
		require_reference(durability)?;
		Ok(Self {
			context,
			digest,
			durability,
		})
	}

	/// Returns the publication effect's context.
	#[must_use]
	pub const fn context(&self) -> PublishIntentContext {
		self.context
	}

	/// Returns the committed receipt's exact digest.
	#[must_use]
	pub const fn digest(&self) -> ReceiptDigest {
		self.digest
	}

	/// Returns the retaining journal reference to the completed kind-9 frame.
	#[must_use]
	pub const fn durability(&self) -> ChainHead {
		self.durability
	}

	/// Encodes the local deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encoded_bytes(&self.encode_bounded()).to_vec()
	}

	/// Decodes a complete canonical kind-18 payload.
	///
	/// # Errors
	///
	/// Rejects malformed or unsupported commitment evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, PublicationRecordError> {
		decode_record(payload, Self::read_body, Self::encode_bounded)
	}

	/// Decodes a frame and checks that the referenced evidence precedes it.
	///
	/// # Errors
	///
	/// Rejects a wrong kind, malformed payload or out-of-order reference.
	pub fn from_frame(frame: &Frame) -> Result<Self, PublicationRecordError> {
		decode_frame(
			frame,
			FrameKind::ReceiptCommitted,
			Self::decode,
			Self::durability,
		)
	}

	/// Checks the exact kind-9 frame and independently measured receipt digest.
	///
	/// The caller supplies frames from the verified chain and checks that the decoded receipt
	/// artifact describes this context and durability frame.
	///
	/// # Errors
	///
	/// Rejects a wrong frame, mismatched context or digest, or invalid durability record.
	pub fn validate_evidence(
		&self,
		durability_frame: &Frame,
		observed_digest: ReceiptDigest,
	) -> Result<(), PublicationRecordError> {
		if self.durability != durability_frame.head() || self.digest != observed_digest {
			return Err(PublicationRecordError::BindingMismatch);
		}
		let durability = DurabilityRecorded::from_frame(durability_frame)?;
		if self.context != durability.context() {
			return Err(PublicationRecordError::BindingMismatch);
		}
		Ok(())
	}

	fn encode_bounded(&self) -> Writer {
		encode_record(&self.context, |encoder| {
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
				.map(2)?
				.u8(0)?
				.u64(JOURNAL_RETENTION_ROOT)?
				.u8(1)?;
			write_reference(encoder, self.durability)
		})
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: PublishIntentContext,
	) -> Result<Self, PublicationRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		let digest = ReceiptDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 1)?;
		if decoder.str()? != LOCAL_RECEIPT_LOCATION {
			return Err(PublicationRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 2)?;
		if decoder.u64()? != RECEIPT_SUCCESS {
			return Err(PublicationRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 3)?;
		if decoder.array()? != Some(1) {
			return Err(PublicationRecordError::UnsupportedEvidence);
		}
		expect_map(decoder, 2)?;
		expect_key(decoder, 0)?;
		if decoder.u64()? != JOURNAL_RETENTION_ROOT {
			return Err(PublicationRecordError::UnsupportedEvidence);
		}
		expect_key(decoder, 1)?;
		let durability = read_reference(decoder)?;
		Self::new(context, digest, durability)
	}
}
