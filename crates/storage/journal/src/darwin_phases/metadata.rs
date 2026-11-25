use std::num::NonZeroU32;

use minicbor::Decoder;

use super::codec::{
	DARWIN_FULL_FILE_BARRIER, PayloadEncoder, PayloadWriteError, decode_record, encode_record,
	expect_code, frame_payload,
};
use super::{
	DarwinPhaseBinding, DarwinPhaseDigest, DarwinPhaseError, DarwinStageSealed,
	DarwinVerificationRecorded,
};
use crate::darwin_prepared::wire::{
	read_entry_header, read_identity, read_timestamp, write_header, write_identity, write_timestamp,
};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{DarwinEntryPrepared, DarwinFileIdentity, DarwinSourceMetadata, OwnerTimestamp};

const KIND: FrameKind = FrameKind::MetadataRecorded;
const BASIC_APFS_FIDELITY: u64 = 1;
const NO_ADDITIONAL_METADATA: u64 = 1;

/// Required managed APFS metadata read back from the stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinRequiredMetadata {
	permissions: DarwinSourceMetadata,
	/// Access time captured before reading the source.
	pub accessed_at: OwnerTimestamp,
	/// Captured source modification time.
	pub modified_at: OwnerTimestamp,
}

impl DarwinRequiredMetadata {
	/// Constructs a descriptor under the strict managed APFS metadata policy.
	///
	/// # Errors
	/// Refuses a mode other than `0600` or an owner outside the admitted Darwin UID range.
	pub fn new(
		mode: u32,
		uid: NonZeroU32,
		gid: u32,
		accessed_at: OwnerTimestamp,
		modified_at: OwnerTimestamp,
	) -> Result<Self, DarwinPhaseError> {
		let permissions = DarwinSourceMetadata::new(mode, uid, gid)
			.map_err(|_| DarwinPhaseError::MetadataMismatch)?;
		Ok(Self {
			permissions,
			accessed_at,
			modified_at,
		})
	}

	/// Returns the stage's checked mode, owner and group.
	#[must_use]
	pub const fn permissions(&self) -> DarwinSourceMetadata {
		self.permissions
	}

	fn write(self, encoder: &mut PayloadEncoder) -> Result<(), PayloadWriteError> {
		encoder
			.map(5)?
			.u8(0)?
			.u32(self.permissions.mode())?
			.u8(1)?
			.u32(self.permissions.owner().get())?
			.u8(2)?
			.u32(self.permissions.group())?
			.u8(3)?;
		write_timestamp(encoder, self.accessed_at)?;
		encoder.u8(4)?;
		write_timestamp(encoder, self.modified_at)
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		expect_map(decoder, 5)?;
		expect_key(decoder, 0)?;
		let mode = decoder.u32()?;
		expect_key(decoder, 1)?;
		let uid = NonZeroU32::new(decoder.u32()?).ok_or(DarwinPhaseError::MetadataMismatch)?;
		expect_key(decoder, 2)?;
		let gid = decoder.u32()?;
		expect_key(decoder, 3)?;
		let accessed_at = read_timestamp(decoder)?;
		expect_key(decoder, 4)?;
		let modified_at = read_timestamp(decoder)?;
		Self::new(mode, uid, gid, accessed_at, modified_at)
	}
}

/// Kind 6 reports the required APFS metadata after application, read-back, and a file barrier.
///
/// The policy requires mode `0600`, UID, GID, access time and modification time, and
/// excludes files with visible extended attributes, resource forks, nonempty effective ACLs,
/// or BSD file flags.
/// Birth and change times, hard-link topology, and sparse allocation fall outside fidelity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinMetadataRecorded {
	binding: DarwinPhaseBinding,
	verification_digest: DarwinPhaseDigest,
	stage: DarwinFileIdentity,
	metadata: DarwinRequiredMetadata,
}

impl DarwinMetadataRecorded {
	/// Records successful required metadata checks and a completed stage `F_FULLFSYNC`.
	///
	/// The coordinator supplies read-back from the held stage and establishes that
	/// both source and stage satisfy the profile's additional metadata restrictions.
	///
	/// # Errors
	/// Rejects differences from the prepared source, verification, or sealed stage.
	pub fn new(
		prepared_frame: &Frame,
		seal: &DarwinStageSealed,
		verification: &DarwinVerificationRecorded,
		stage: DarwinFileIdentity,
		metadata: DarwinRequiredMetadata,
	) -> Result<Self, DarwinPhaseError> {
		let record = Self {
			binding: verification.binding(),
			verification_digest: verification.record_digest(),
			stage,
			metadata,
		};
		record.check_prerequisites(prepared_frame, seal, verification)?;
		Ok(record)
	}

	/// Returns the signed-owner and model-stage association.
	#[must_use]
	pub const fn binding(&self) -> DarwinPhaseBinding {
		self.binding
	}

	/// Returns the stage identity observed during metadata read-back.
	#[must_use]
	pub const fn stage(&self) -> DarwinFileIdentity {
		self.stage
	}

	/// Returns the completed stage's metadata read-back.
	#[must_use]
	pub const fn metadata(&self) -> DarwinRequiredMetadata {
		self.metadata
	}

	/// Binds the exact canonical metadata payload.
	#[must_use]
	pub fn record_digest(&self) -> DarwinPhaseDigest {
		DarwinPhaseDigest::of(KIND, &self.encode())
	}

	/// Encodes kind 6 under the managed APFS profile.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(|encoder| {
			write_header(encoder, self.binding.context, Some(self.binding.entry))?;
			encoder.map(7)?.u8(0)?;
			self.binding.write(encoder)?;
			encoder
				.u8(1)?
				.bytes(self.verification_digest.as_bytes())?
				.u8(2)?;
			write_identity(encoder, self.stage)?;
			encoder.u8(3)?.u64(BASIC_APFS_FIDELITY)?.u8(4)?;
			self.metadata.write(encoder)?;
			encoder
				.u8(5)?
				.u64(NO_ADDITIONAL_METADATA)?
				.u8(6)?
				.u64(DARWIN_FULL_FILE_BARRIER)?;
			Ok(())
		})
	}

	/// Decodes one complete managed APFS metadata payload.
	///
	/// # Errors
	/// Returns an error for malformed, noncanonical, or incompatible evidence.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPhaseError> {
		decode_record(payload, Self::read, Self::encode)
	}

	/// Checks the discriminator and decodes one complete metadata frame.
	///
	/// # Errors
	/// Returns an error for a wrong discriminator or an invalid payload.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPhaseError> {
		Self::decode(frame_payload(frame, KIND)?)
	}

	/// Checks the exact preparation, seal, read-back and required metadata.
	///
	/// # Errors
	/// Returns an error if a prerequisite record or its observations differ.
	pub fn check_prerequisites(
		&self,
		prepared_frame: &Frame,
		seal: &DarwinStageSealed,
		verification: &DarwinVerificationRecorded,
	) -> Result<(), DarwinPhaseError> {
		self.validated_preparation(prepared_frame, seal, verification)
			.map(|_| ())
	}

	pub(super) fn validated_preparation<'a>(
		&self,
		prepared_frame: &'a Frame,
		seal: &DarwinStageSealed,
		verification: &DarwinVerificationRecorded,
	) -> Result<DarwinEntryPrepared<'a>, DarwinPhaseError> {
		let prepared = verification.validated_preparation(prepared_frame, seal)?;
		if self.binding != verification.binding()
			|| self.verification_digest != verification.record_digest()
		{
			return Err(DarwinPhaseError::BindingMismatch);
		}
		if self.stage != verification.stage().identity {
			return Err(DarwinPhaseError::IdentityMismatch);
		}
		let source = prepared.preparation().source;
		let expected = DarwinRequiredMetadata {
			permissions: source.metadata(),
			accessed_at: source.times().accessed_at,
			modified_at: source.times().modified_at,
		};
		if self.metadata != expected {
			return Err(DarwinPhaseError::MetadataMismatch);
		}
		Ok(prepared)
	}

	fn read(decoder: &mut Decoder<'_>) -> Result<Self, DarwinPhaseError> {
		let (context, entry) = read_entry_header(decoder)?;
		expect_map(decoder, 7)?;
		expect_key(decoder, 0)?;
		let binding = DarwinPhaseBinding::read(decoder, context, entry)?;
		expect_key(decoder, 1)?;
		let verification_digest = DarwinPhaseDigest::from_bytes(read_fixed(decoder)?);
		expect_key(decoder, 2)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 3)?;
		expect_code(decoder, BASIC_APFS_FIDELITY)?;
		expect_key(decoder, 4)?;
		let metadata = DarwinRequiredMetadata::read(decoder)?;
		expect_key(decoder, 5)?;
		expect_code(decoder, NO_ADDITIONAL_METADATA)?;
		expect_key(decoder, 6)?;
		expect_code(decoder, DARWIN_FULL_FILE_BARRIER)?;
		Ok(Self {
			binding,
			verification_digest,
			stage,
			metadata,
		})
	}
}
