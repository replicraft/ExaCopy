use exacopy_endpoint::MAX_FILE_LENGTH;
use exacopy_model::checked_range_end;
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use super::codec::{decode_frame, decode_record, encode_record, expect_evidence};
use super::{StreamDigest, VerificationRecordError};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{JournalContext, JournalEntryId};

/// The largest checkpoint ordinal supported by Linux local v1.
pub const MAX_RANGE_CHECKPOINTS: u32 = 4096;
/// The largest logical byte count measured by one checkpoint page.
pub const MAX_CHECKPOINT_RANGE_BYTES: u64 = 64 * 1024 * 1024;
/// The maximum size in bytes of a canonical range page.
pub const MAX_RANGE_PAGE_BYTES: usize = 95;

const PAGE_FORMAT_VERSION: u64 = 1;
const UNNAMED_STREAM_INDEX: u64 = 0;
const DATA_BARRIER_COMPLETED: u64 = 1;
const PAGE_DIGEST_DOMAIN: &[u8] = b"ExaCopy/local-range-page/v1\0";
const SOURCE_MEASUREMENT_DOMAIN: &[u8] = b"ExaCopy/local-source-observation/v1\0";

/// Identifies the original source observation from the canonical entry preparation payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceMeasurementId([u8; 32]);

impl SourceMeasurementId {
	/// Binds the exact, already validated `EntryPrepared` payload under the local source domain.
	#[must_use]
	pub fn from_prepared_payload(payload: &[u8]) -> Self {
		Self(domain_digest(SOURCE_MEASUREMENT_DOMAIN, payload))
	}

	/// Returns the encoded measurement identifier.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// A reference to an immutable canonical range page owned by the job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangePageRef {
	digest: [u8; 32],
	byte_length: usize,
	ordinal: u32,
}

impl RangePageRef {
	/// Returns the domain-separated digest of the canonical page bytes.
	#[must_use]
	pub const fn digest(&self) -> &[u8; 32] {
		&self.digest
	}

	/// Returns the exact encoded byte count expected from the referenced page.
	#[must_use]
	pub const fn byte_length(self) -> usize {
		self.byte_length
	}

	/// Returns the page's ordinal in the checkpoint inventory, starting at one.
	#[must_use]
	pub const fn ordinal(self) -> u32 {
		self.ordinal
	}
}

/// One measured half-open range of the unnamed regular-file stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangePage {
	ordinal: u32,
	offset: u64,
	length: u64,
	digest: StreamDigest,
	source: SourceMeasurementId,
}

impl RangePage {
	/// Constructs an immutable range page with a bounded ordinal and range.
	///
	/// # Errors
	/// Returns an error if the ordinal is outside the local inventory, the length
	/// is zero or exceeds 64 MiB, or the exclusive range end exceeds the file limit.
	pub fn new(
		ordinal: u32,
		offset: u64,
		length: u64,
		digest: StreamDigest,
		source: SourceMeasurementId,
	) -> Result<Self, VerificationRecordError> {
		check_ordinal(ordinal)?;
		if length > MAX_CHECKPOINT_RANGE_BYTES
			|| checked_range_end(MAX_FILE_LENGTH, offset, length).is_none()
		{
			return Err(VerificationRecordError::InvalidCheckpointRange);
		}
		Ok(Self {
			ordinal,
			offset,
			length,
			digest,
			source,
		})
	}

	/// Returns the page's ordinal in the checkpoint inventory, starting at one.
	#[must_use]
	pub const fn ordinal(&self) -> u32 {
		self.ordinal
	}

	/// Returns the first logical byte offset of the range.
	#[must_use]
	pub const fn offset(&self) -> u64 {
		self.offset
	}

	/// Returns the number of logical bytes in the range.
	#[must_use]
	pub const fn length(&self) -> u64 {
		self.length
	}

	/// Returns the standard BLAKE3-256 digest of exactly the measured range bytes.
	#[must_use]
	pub const fn digest(&self) -> StreamDigest {
		self.digest
	}

	/// Returns the source observation associated with the range.
	#[must_use]
	pub const fn source(&self) -> SourceMeasurementId {
		self.source
	}

	/// Returns the digest, encoded length, and ordinal that bind this page.
	#[must_use]
	pub fn reference(&self) -> RangePageRef {
		let encoded = self.encode();
		RangePageRef {
			digest: domain_digest(PAGE_DIGEST_DOMAIN, &encoded),
			byte_length: encoded.len(),
			ordinal: self.ordinal,
		}
	}

	/// Encodes this immutable page as deterministic CBOR without journal framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		// One map header, seven one-byte keys, 19 bytes for the bounded
		// integer fields, and two 34-byte byte strings.
		let mut encoder = Encoder::new(Cursor::new([0; MAX_RANGE_PAGE_BYTES]));
		encoder
			.map(7)
			.and_then(|encoder| {
				encoder
					.u8(0)?
					.u64(PAGE_FORMAT_VERSION)?
					.u8(1)?
					.u32(self.ordinal)?
					.u8(2)?
					.u64(UNNAMED_STREAM_INDEX)?
					.u8(3)?
					.u64(self.offset)?
					.u8(4)?
					.u64(self.length)?
					.u8(5)?
					.bytes(self.digest.as_bytes())?
					.u8(6)?
					.bytes(self.source.as_bytes())
			})
			.expect("canonical local range page fits the maximum page size");
		let writer = encoder.into_writer();
		writer.get_ref()[..writer.position()].to_vec()
	}

	/// Decodes a complete canonical range page.
	///
	/// # Errors
	/// Returns a typed error for malformed or unsupported evidence.
	pub fn decode(bytes: &[u8]) -> Result<Self, VerificationRecordError> {
		if bytes.len() > MAX_RANGE_PAGE_BYTES {
			return Err(VerificationRecordError::PayloadTooLong);
		}
		let mut decoder = Decoder::new(bytes);
		expect_map(&mut decoder, 7)?;
		expect_key(&mut decoder, 0)?;
		expect_evidence(&mut decoder, PAGE_FORMAT_VERSION)?;
		expect_key(&mut decoder, 1)?;
		let ordinal = decoder.u32()?;
		expect_key(&mut decoder, 2)?;
		expect_evidence(&mut decoder, UNNAMED_STREAM_INDEX)?;
		expect_key(&mut decoder, 3)?;
		let offset = decoder.u64()?;
		expect_key(&mut decoder, 4)?;
		let length = decoder.u64()?;
		expect_key(&mut decoder, 5)?;
		let digest = StreamDigest::from_bytes(read_fixed(&mut decoder)?);
		expect_key(&mut decoder, 6)?;
		let source = SourceMeasurementId(read_fixed(&mut decoder)?);
		let page = Self::new(ordinal, offset, length, digest, source)?;
		if decoder.position() != bytes.len() {
			return Err(VerificationRecordError::TrailingBytes);
		}
		if page.encode() != bytes {
			return Err(VerificationRecordError::NonCanonical);
		}
		Ok(page)
	}
}

/// A local kind-3 record referring to range data after a completed stage data barrier.
///
/// Replay must match this record to the prepared entry and the immutable page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeCheckpoint {
	/// Job and plan context.
	pub context: JournalContext,
	/// The prepared entry bound to the range data.
	pub entry: JournalEntryId,
	/// The immutable page containing the range and its digest.
	pub page: RangePageRef,
	/// The original source observation this checkpoint refers to.
	pub source: SourceMeasurementId,
}

impl RangeCheckpoint {
	/// Encodes the local deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder
				.map(3)?
				.u8(0)?
				.map(3)?
				.u8(0)?
				.bytes(self.page.digest())?
				.u8(1)?
				.u64(u64::try_from(self.page.byte_length()).expect("bounded range page size"))?
				.u8(2)?
				.u32(self.page.ordinal())?
				.u8(1)?
				.bytes(self.source.as_bytes())?
				.u8(2)?
				.u64(DATA_BARRIER_COMPLETED)?;
			Ok(())
		})
	}

	/// Decodes a complete local deterministic CBOR kind-3 payload.
	///
	/// # Errors
	/// Returns a typed error for malformed or unsupported evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, VerificationRecordError> {
		decode_record(payload, Self::read_body, Self::encode)
	}

	/// Checks the frame discriminator before decoding its complete payload.
	///
	/// # Errors
	/// Returns an error for a wrong frame kind or malformed payload.
	pub fn from_frame(frame: &Frame) -> Result<Self, VerificationRecordError> {
		decode_frame(frame, FrameKind::RangeCheckpoint, Self::decode)
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, VerificationRecordError> {
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		let digest = read_fixed(decoder)?;
		expect_key(decoder, 1)?;
		let byte_length = usize::try_from(decoder.u64()?)
			.map_err(|_| VerificationRecordError::InvalidRangePageLength)?;
		if !(1..=MAX_RANGE_PAGE_BYTES).contains(&byte_length) {
			return Err(VerificationRecordError::InvalidRangePageLength);
		}
		expect_key(decoder, 2)?;
		let ordinal = decoder.u32()?;
		check_ordinal(ordinal)?;
		expect_key(decoder, 1)?;
		let source = SourceMeasurementId(read_fixed(decoder)?);
		expect_key(decoder, 2)?;
		expect_evidence(decoder, DATA_BARRIER_COMPLETED)?;
		Ok(Self {
			context,
			entry,
			page: RangePageRef {
				digest,
				byte_length,
				ordinal,
			},
			source,
		})
	}
}

fn check_ordinal(ordinal: u32) -> Result<(), VerificationRecordError> {
	if ordinal == 0 || ordinal > MAX_RANGE_CHECKPOINTS {
		return Err(VerificationRecordError::InvalidRangeOrdinal);
	}
	Ok(())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
	*blake3::Hasher::new()
		.update(domain)
		.update(bytes)
		.finalize()
		.as_bytes()
}
