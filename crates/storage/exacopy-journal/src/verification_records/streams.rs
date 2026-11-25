use exacopy_endpoint::MAX_FILE_LENGTH;
use minicbor::Decoder;

use super::VerificationRecordError;
use super::codec::{
	PayloadEncoder, PayloadWriteError, decode_frame, decode_record, encode_record, expect_array,
	expect_evidence,
};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed, read_identity, write_identity};
use crate::{JournalContext, JournalEntryId, LinuxFileIdentity, VerificationDigest};

const SYNCHRONOUS_WRITER_COUNT: u64 = 1;
const FILE_BARRIER_COMPLETED: u64 = 1;
const BLAKE3_256_READBACK: u64 = 1;
const RECORD_DIGEST_DOMAIN: &[u8] = b"ExaCopy/journal-verification/v1\0";

/// Logical length of an unnamed regular-file stream supported by the local adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLength(u64);

impl StreamLength {
	/// Validates a logical stream length against the signed file extent limit.
	///
	/// # Errors
	/// Returns an error if the length exceeds the local file extent limit.
	pub const fn new(length: u64) -> Result<Self, VerificationRecordError> {
		if length > MAX_FILE_LENGTH {
			return Err(VerificationRecordError::UnsupportedLength);
		}
		Ok(Self(length))
	}
	/// Returns the recorded logical byte count.
	#[must_use]
	pub const fn get(self) -> u64 {
		self.0
	}
}

/// A local kind-4 record after the synchronous stage writer released its file.
///
/// The profile records one joined writer, the sealed stage's sole stream length,
/// and a completed file barrier. It carries an observation in the recorded run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageSealed {
	/// Job and plan context.
	pub context: JournalContext,
	/// The staged entry.
	pub entry: JournalEntryId,
	/// The observed identity of the closed stage.
	pub stage: LinuxFileIdentity,
	/// The exact logical length of the unnamed stream on that stage.
	pub length: StreamLength,
}

impl StageSealed {
	/// Encodes the local deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder.map(4)?.u64(0)?.array(1)?.map(2)?.u64(0)?;
			write_identity(encoder, self.stage)?;
			encoder
				.u64(1)?
				.u64(self.length.get())?
				.u64(1)?
				.u64(SYNCHRONOUS_WRITER_COUNT)?
				.u64(2)?
				.u64(self.context.epoch.get())?
				.u64(3)?
				.u64(FILE_BARRIER_COMPLETED)?;
			Ok(())
		})
	}

	/// Decodes a complete local deterministic CBOR kind-4 payload.
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
		decode_frame(frame, FrameKind::StageSealed, Self::decode)
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, VerificationRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		expect_array(decoder, 1)?;
		expect_map(decoder, 2)?;
		expect_key(decoder, 0)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 1)?;
		let length = StreamLength::new(decoder.u64()?)?;
		expect_key(decoder, 1)?;
		expect_evidence(decoder, SYNCHRONOUS_WRITER_COUNT)?;
		expect_key(decoder, 2)?;
		if decoder.u64()? != context.epoch.get() {
			return Err(VerificationRecordError::EpochMismatch);
		}
		expect_key(decoder, 3)?;
		expect_evidence(decoder, FILE_BARRIER_COMPLETED)?;
		Ok(Self {
			context,
			entry,
			stage,
			length,
		})
	}
}

/// A complete BLAKE3-256 measurement and its native file identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamEvidence {
	/// Observed native identity during measurement.
	pub identity: LinuxFileIdentity,
	/// Logical byte count independently measured.
	pub length: StreamLength,
	/// The standard whole-stream digest.
	pub digest: StreamDigest,
}

/// A standard unkeyed BLAKE3-256 digest of the observed logical byte stream.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StreamDigest([u8; 32]);

impl StreamDigest {
	/// Wraps the digest returned by the whole-stream content measurement.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the 32-byte recorded digest.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// A local kind-5 record describing independent BLAKE3-256 stage read-back.
///
/// This payload reports matching content evidence for the observed files.
/// A restart must reestablish filesystem identity and verification separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationRecorded {
	/// Job and plan context.
	pub context: JournalContext,
	/// The verified entry.
	pub entry: JournalEntryId,
	source: StreamEvidence,
	stage: StreamEvidence,
}

impl VerificationRecorded {
	/// Records exact length and digest agreement for two distinct native identities.
	///
	/// # Errors
	/// Returns an error if the identities alias or measured lengths or digests differ.
	pub fn new(
		context: JournalContext,
		entry: JournalEntryId,
		source: StreamEvidence,
		stage: StreamEvidence,
	) -> Result<Self, VerificationRecordError> {
		if source.identity == stage.identity {
			return Err(VerificationRecordError::AliasedIdentity);
		}
		if source.length != stage.length || source.digest != stage.digest {
			return Err(VerificationRecordError::MismatchedStreams);
		}
		Ok(Self {
			context,
			entry,
			source,
			stage,
		})
	}

	/// Source-stream measurement.
	#[must_use]
	pub const fn source(&self) -> StreamEvidence {
		self.source
	}

	/// Independent stage read-back measurement.
	#[must_use]
	pub const fn stage(&self) -> StreamEvidence {
		self.stage
	}

	/// Binds the complete canonical record under `ExaCopy/journal-verification/v1\0`.
	#[must_use]
	pub fn record_digest(&self) -> VerificationDigest {
		let mut hasher = blake3::Hasher::new();
		hasher.update(RECORD_DIGEST_DOMAIN).update(&self.encode());
		VerificationDigest::from_bytes(*hasher.finalize().as_bytes())
	}

	/// Encodes the local deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder.map(4)?.u64(0)?.u64(BLAKE3_256_READBACK)?.u64(1)?;
			write_identity(encoder, self.source.identity)?;
			encoder.u64(2)?;
			write_identity(encoder, self.stage.identity)?;
			encoder.u64(3)?.array(2)?;
			write_measurement(encoder, self.source)?;
			write_measurement(encoder, self.stage)
		})
	}

	/// Decodes a complete local deterministic CBOR kind-5 payload.
	///
	/// # Errors
	/// Returns a typed error for malformed, incompatible or mismatched evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, VerificationRecordError> {
		decode_record(payload, Self::read_body, Self::encode)
	}

	/// Checks the frame discriminator before decoding its complete payload.
	///
	/// # Errors
	/// Returns an error for a wrong frame kind or malformed payload.
	pub fn from_frame(frame: &Frame) -> Result<Self, VerificationRecordError> {
		decode_frame(frame, FrameKind::VerificationRecorded, Self::decode)
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, VerificationRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		expect_evidence(decoder, BLAKE3_256_READBACK)?;
		expect_key(decoder, 1)?;
		let source = read_identity(decoder)?;
		expect_key(decoder, 2)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		expect_array(decoder, 2)?;
		let source = read_measurement(decoder, source)?;
		let stage = read_measurement(decoder, stage)?;
		Self::new(context, entry, source, stage)
	}
}

fn write_measurement(
	encoder: &mut PayloadEncoder,
	stream: StreamEvidence,
) -> Result<(), PayloadWriteError> {
	encoder
		.map(2)?
		.u64(0)?
		.u64(stream.length.get())?
		.u64(1)?
		.bytes(stream.digest.as_bytes())?;
	Ok(())
}

fn read_measurement(
	decoder: &mut Decoder<'_>,
	identity: LinuxFileIdentity,
) -> Result<StreamEvidence, VerificationRecordError> {
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let length = StreamLength::new(decoder.u64()?)?;
	expect_key(decoder, 1)?;
	let digest = StreamDigest::from_bytes(read_fixed(decoder)?);
	Ok(StreamEvidence {
		identity,
		length,
		digest,
	})
}
