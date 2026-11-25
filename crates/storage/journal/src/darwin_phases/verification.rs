use minicbor::Decoder;

use super::codec::{
	PayloadEncoder, PayloadWriteError, decode_record, encode_record, expect_code, frame_payload,
};
use super::{DarwinPhaseBinding, DarwinPhaseDigest, DarwinPhaseError, DarwinStageSealed};
use crate::darwin_prepared::wire::{
	read_entry_header, read_identity, write_header, write_identity,
};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{DarwinEntryPrepared, DarwinFileIdentity, StreamDigest, StreamLength};

const KIND: FrameKind = FrameKind::VerificationRecorded;
const BLAKE3_256_READBACK: u64 = 1;

/// A complete unnamed-stream measurement observed on a held managed APFS file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinStreamEvidence {
	/// Exact native identity observed during measurement.
	pub identity: DarwinFileIdentity,
	/// Total logical bytes observed through EOF.
	pub length: StreamLength,
	/// Standard unkeyed BLAKE3-256 of the observed bytes.
	pub digest: StreamDigest,
}

impl DarwinStreamEvidence {
	pub(super) fn write(self, encoder: &mut PayloadEncoder) -> Result<(), PayloadWriteError> {
		encoder.map(3)?.u8(0)?;
		write_identity(encoder, self.identity)?;
		encoder
			.u8(1)?
			.u64(self.length.get())?
			.u8(2)?
			.bytes(self.digest.as_bytes())?;
		Ok(())
	}

	pub(super) fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		expect_map(decoder, 3)?;
		expect_key(decoder, 0)?;
		let identity = read_identity(decoder)?;
		expect_key(decoder, 1)?;
		let length =
			StreamLength::new(decoder.u64()?).map_err(|_| DarwinPhaseError::StreamMismatch)?;
		expect_key(decoder, 2)?;
		let digest = StreamDigest::from_bytes(read_fixed(decoder)?);
		Ok(Self {
			identity,
			length,
			digest,
		})
	}
}

/// Kind 5 records matching source and independent post-close stage read-back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinVerificationRecorded {
	binding: DarwinPhaseBinding,
	seal_digest: DarwinPhaseDigest,
	source: DarwinStreamEvidence,
	stage: DarwinStreamEvidence,
}

impl DarwinVerificationRecorded {
	/// Associates separately measured streams with the exact prepared and sealed stage.
	///
	/// # Errors
	/// Rejects aliased files, different extents or digests, and conflicting prior observations.
	pub fn new(
		prepared_frame: &Frame,
		seal: &DarwinStageSealed,
		source: DarwinStreamEvidence,
		stage: DarwinStreamEvidence,
	) -> Result<Self, DarwinPhaseError> {
		Self::check_streams(source, stage)?;
		let record = Self {
			binding: seal.binding(),
			seal_digest: seal.record_digest(),
			source,
			stage,
		};
		record.check_prerequisites(prepared_frame, seal)?;
		Ok(record)
	}

	/// Returns the signed-owner and model-stage association.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.binding
	}

	/// Returns the source stream measurement.
	#[must_use]
	pub const fn source(&self) -> DarwinStreamEvidence {
		self.source
	}

	/// Returns the independently measured stage stream.
	#[must_use]
	pub const fn stage(&self) -> DarwinStreamEvidence {
		self.stage
	}

	/// Binds the exact canonical verification payload.
	#[must_use]
	pub fn record_digest(&self) -> DarwinPhaseDigest {
		DarwinPhaseDigest::of(KIND, &self.encode())
	}

	/// Encodes kind 5 under the managed APFS profile.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			write_header(encoder, self.binding.context, Some(self.binding.entry))?;
			encoder.map(5)?.u8(0)?;
			self.binding.write(encoder)?;
			encoder
				.u8(1)?
				.bytes(self.seal_digest.as_bytes())?
				.u8(2)?
				.u64(BLAKE3_256_READBACK)?
				.u8(3)?;
			self.source.write(encoder)?;
			encoder.u8(4)?;
			self.stage.write(encoder)
		})
	}

	/// Decodes one complete managed APFS read-back payload.
	///
	/// # Errors
	/// Returns an error for malformed, noncanonical, or conflicting measurements.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Checks the discriminator and decodes one complete verification frame.
	///
	/// # Errors
	/// Returns an error for a wrong discriminator or an invalid payload.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		Self::decode(frame_payload(frame, KIND)?)
	}

	/// Checks the exact preparation, seal, and both native file observations.
	///
	/// # Errors
	/// Returns an error if a prerequisite record or its observations differ.
	pub fn check_prerequisites(
		&self,
		prepared_frame: &Frame,
		seal: &DarwinStageSealed,
	) -> Result<(), DarwinPhaseError> {
		self.validated_preparation(prepared_frame, seal).map(|_| ())
	}

	pub(super) fn validated_preparation<'a>(
		&self,
		prepared_frame: &'a Frame,
		seal: &DarwinStageSealed,
	) -> Result<DarwinEntryPrepared<'a>, DarwinPhaseError> {
		let prepared = seal.validated_preparation(prepared_frame)?;
		if self.binding != seal.binding() || self.seal_digest != seal.record_digest() {
			return Err(DarwinPhaseError::BindingMismatch);
		}
		if self.source.identity != prepared.preparation().source.identity()
			|| self.stage.identity != seal.stage()
		{
			return Err(DarwinPhaseError::IdentityMismatch);
		}
		if self.stage.length != seal.length() {
			return Err(DarwinPhaseError::StreamMismatch);
		}
		Ok(prepared)
	}

	fn check_streams(
		source: DarwinStreamEvidence,
		stage: DarwinStreamEvidence,
	) -> Result<(), DarwinPhaseError> {
		if source.identity.may_alias(stage.identity) {
			return Err(DarwinPhaseError::AliasedIdentity);
		}
		if source.length != stage.length || source.digest != stage.digest {
			return Err(DarwinPhaseError::StreamMismatch);
		}
		Ok(())
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let (context, entry) = read_entry_header(decoder)?;
		expect_map(decoder, 5)?;
		expect_key(decoder, 0)?;
		let binding = DarwinPhaseBinding::read(decoder, context, entry)?;
		expect_key(decoder, 1)?;
		let seal_digest = DarwinPhaseDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 2)?;
		expect_code(decoder, BLAKE3_256_READBACK)?;
		expect_key(decoder, 3)?;
		let source = DarwinStreamEvidence::read(decoder)?;
		expect_key(decoder, 4)?;
		let stage = DarwinStreamEvidence::read(decoder)?;
		Self::check_streams(source, stage)?;
		Ok(Self {
			binding,
			seal_digest,
			source,
			stage,
		})
	}
}
