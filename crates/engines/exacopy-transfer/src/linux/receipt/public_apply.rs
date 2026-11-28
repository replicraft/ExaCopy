use std::fmt;

use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	ApplyQualificationDigest, ApprovedPublicPlanDigest, OwnerDigest, PublicApplyAssociation,
	PublicApplyIntent, PublicPlanEntryId, ReceiptDigest,
};
use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::{CopyReceipt, MAX_COPY_RECEIPT_BYTES, ReceiptError, read_array, read_fixed, read_key};

mod commit;
#[cfg(test)]
mod tests;

pub use commit::{PublicApplyCommitError, PublicApplyCommitSelection};

const VERSION: [u64; 3] = [2, 0, 1];
const FIELDS: u64 = 5;
const PUBLIC_APPLY_RECEIPT_DOMAIN: &[u8] = b"ExaCopy/linux-public-apply-receipt/v1\0";

// Version, association, intent reference, qualification digest and CBOR headers.
const WRAPPER_OVERHEAD_LIMIT: usize = 180;

/// Maximum bytes of a canonical private public-apply receipt.
pub const MAX_PUBLIC_APPLY_RECEIPT_BYTES: usize = MAX_COPY_RECEIPT_BYTES + WRAPPER_OVERHEAD_LIMIT;

type Buffer = Cursor<[u8; MAX_PUBLIC_APPLY_RECEIPT_BYTES]>;
type EncodeError = encode::Error<EndOfArray>;

/// Required private receipt artifact for a completed public-apply effect.
///
/// This format binds both Plan domains, the signed local owner, the exact intent
/// and qualification. The byte format carries recorded claims. A coordinator
/// or inspector separately verifies the authoritative journal and live evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicApplyReceipt<'name> {
	private: CopyReceipt<'name>,
	association: PublicApplyAssociation,
	intent: ChainHead,
	qualification: ApplyQualificationDigest,
}

impl<'name> PublicApplyReceipt<'name> {
	/// Creates one mandatory artifact using the exact private publication evidence.
	///
	/// # Errors
	/// Refuses invalid attempt and incompatible journal frame positions.
	pub fn new(
		private: CopyReceipt<'name>,
		association: PublicApplyAssociation,
		intent: ChainHead,
		qualification: ApplyQualificationDigest,
	) -> Result<Self, PublicApplyReceiptError> {
		let evidence = private.evidence();
		if evidence.context.epoch.get() == 0
			|| evidence.entry.as_bytes() == &[0; 16]
			|| intent == ChainHead::start()
			|| intent.sequence().checked_add(2) != Some(private.durability_frame().sequence())
		{
			return Err(PublicApplyReceiptError::Binding);
		}
		Ok(Self {
			private,
			association,
			intent,
			qualification,
		})
	}

	/// Returns the recorded private copy evidence and exact durability frame.
	#[must_use]
	pub const fn private(&self) -> &CopyReceipt<'name> {
		&self.private
	}

	/// Returns the recorded signed-owner, public Plan and public entry association.
	#[must_use]
	pub const fn association(&self) -> PublicApplyAssociation {
		self.association
	}

	/// Returns the exact public intent reference recorded in the receipt.
	#[must_use]
	pub const fn intent(&self) -> ChainHead {
		self.intent
	}

	/// Returns the independently selected qualification record digest.
	#[must_use]
	pub const fn qualification(&self) -> ApplyQualificationDigest {
		self.qualification
	}

	/// Compares the recorded effect and association against the supplied intent and frame head.
	///
	/// The caller must establish that the head is for this intent in the validated journal,
	/// and independently verify the owner, qualification and actual stream evidence.
	#[must_use]
	pub fn matches_intent(&self, head: ChainHead, intent: &PublicApplyIntent<'_>) -> bool {
		let received = self.private.evidence();
		let expected = intent.private();
		let evidence = intent.evidence();
		self.intent == head
			&& evidence.metadata.sequence().checked_add(1) == Some(head.sequence())
			&& self.association == intent.association()
			&& self.qualification == evidence.qualification.record
			&& received.context.job == expected.context.job
			&& received.context.epoch == expected.context.epoch
			&& received.context.plan_digest == expected.context.plan_digest
			&& received.entry == expected.context.entry
			&& received.destination.identity == expected.target.parent
			&& received.target == expected.target.component
			&& received.stream.identity == expected.target.stage
	}

	/// Encodes the mandatory v2 wrapper and its canonical inner v1 artifact.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let encoded = self.encoded();
		encoded.get_ref()[..encoded.position()].to_vec()
	}

	/// Returns the domain-specific digest of the exact public receipt wrapper.
	#[must_use]
	pub fn digest(&self) -> ReceiptDigest {
		let encoded = self.encoded();
		let mut hasher = blake3::Hasher::new();
		hasher.update(PUBLIC_APPLY_RECEIPT_DOMAIN);
		hasher.update(&encoded.get_ref()[..encoded.position()]);
		ReceiptDigest::from_bytes(*hasher.finalize().as_bytes())
	}

	/// Decodes one bounded canonical public receipt.
	///
	/// # Errors
	/// Refuses unknown formats and features, malformed, noncanonical or inconsistent fields.
	pub fn decode(input: &'name [u8]) -> Result<Self, PublicApplyReceiptError> {
		if input.len() > MAX_PUBLIC_APPLY_RECEIPT_BYTES {
			return Err(PublicApplyReceiptError::Length);
		}
		let mut decoder = Decoder::new(input);
		if decoder.map()? != Some(FIELDS) {
			return Err(PublicApplyReceiptError::InvalidCbor);
		}
		read_key(&mut decoder, 0)?;
		read_array(&mut decoder, 3)?;
		for value in VERSION {
			if decoder.u64()? != value {
				return Err(PublicApplyReceiptError::UnsupportedVersion);
			}
		}
		read_key(&mut decoder, 1)?;
		let private = CopyReceipt::decode(decoder.bytes()?)
			.map_err(PublicApplyReceiptError::PrivateReceipt)?;
		read_key(&mut decoder, 2)?;
		read_array(&mut decoder, 3)?;
		let association = PublicApplyAssociation {
			owner_digest: OwnerDigest::from_bytes(read_fixed(&mut decoder)?),
			public_plan: ApprovedPublicPlanDigest::from_bytes(read_fixed(&mut decoder)?),
			public_entry: PublicPlanEntryId::from_bytes(read_fixed(&mut decoder)?)
				.map_err(|_| PublicApplyReceiptError::Binding)?,
		};
		read_key(&mut decoder, 3)?;
		read_array(&mut decoder, 2)?;
		let intent = ChainHead::after(decoder.u64()?, read_fixed(&mut decoder)?)
			.ok_or(PublicApplyReceiptError::Binding)?;
		read_key(&mut decoder, 4)?;
		let qualification = ApplyQualificationDigest::from_bytes(read_fixed(&mut decoder)?);
		let receipt = Self::new(private, association, intent, qualification)?;
		let expected = receipt.encoded();
		if expected.get_ref()[..expected.position()] != *input {
			return Err(PublicApplyReceiptError::NonCanonical);
		}
		Ok(receipt)
	}

	fn encoded(&self) -> Buffer {
		let mut encoder = Encoder::new(Buffer::new([0; MAX_PUBLIC_APPLY_RECEIPT_BYTES]));
		self.write(&mut encoder)
			.expect("validated receipt fits the fixed public receipt bound");
		encoder.into_writer()
	}

	fn write(&self, encoder: &mut Encoder<Buffer>) -> Result<(), EncodeError> {
		encoder.map(FIELDS)?.u8(0)?.array(3)?;
		for value in VERSION {
			encoder.u64(value)?;
		}
		let private = self.private.encoded();
		encoder
			.u8(1)?
			.bytes(&private.get_ref()[..private.position()])?
			.u8(2)?
			.array(3)?
			.bytes(self.association.owner_digest.as_bytes())?
			.bytes(self.association.public_plan.as_bytes())?
			.bytes(self.association.public_entry.as_bytes())?
			.u8(3)?
			.array(2)?
			.u64(self.intent.sequence())?
			.bytes(&self.intent.digest())?
			.u8(4)?
			.bytes(self.qualification.as_bytes())?;
		Ok(())
	}
}

/// Why a required private public-apply receipt was refused.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublicApplyReceiptError {
	/// The artifact exceeds the selected byte limit.
	Length,
	/// The CBOR fields have an invalid shape or fixed size.
	InvalidCbor,
	/// The artifact is noncanonical or has trailing bytes.
	NonCanonical,
	/// The version or required features are unsupported.
	UnsupportedVersion,
	/// A required identity or exact frame relationship is invalid.
	Binding,
	/// The mandatory canonical inner copy receipt was refused.
	PrivateReceipt(ReceiptError),
}

impl From<minicbor::decode::Error> for PublicApplyReceiptError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::InvalidCbor
	}
}

impl From<ReceiptError> for PublicApplyReceiptError {
	fn from(_: ReceiptError) -> Self {
		Self::InvalidCbor
	}
}

impl fmt::Display for PublicApplyReceiptError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::Length => "public apply receipt exceeds its byte limit",
			Self::InvalidCbor => "public apply receipt has invalid CBOR fields",
			Self::NonCanonical => "public apply receipt is not canonical",
			Self::UnsupportedVersion => {
				"public apply receipt version or required features are unsupported"
			}
			Self::Binding => "public apply receipt identities or frame relationships disagree",
			Self::PrivateReceipt(error) => {
				return write!(formatter, "inner private receipt refused ({error})");
			}
		};
		formatter.write_str(message)
	}
}

impl std::error::Error for PublicApplyReceiptError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::PrivateReceipt(error) => Some(error),
			_ => None,
		}
	}
}
