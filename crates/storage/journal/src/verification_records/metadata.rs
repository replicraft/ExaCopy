use minicbor::Decoder;

use super::VerificationRecordError;
use super::codec::{
	PayloadEncoder, PayloadWriteError, decode_frame, decode_record, encode_record, expect_array,
	expect_evidence,
};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_identity, write_identity};
use crate::{JournalContext, JournalEntryId, LinuxFileIdentity, OwnerTimestamp};

const ORDINARY_PERMISSION_MASK: u32 = 0o777;
const LINUX_BASIC_METADATA: u64 = 1;
const METADATA_BARRIER_COMPLETED: u64 = 1;

const METADATA_OMISSIONS: [MetadataOmission; 4] = [
	MetadataOmission::HiddenExtendedAttributes,
	MetadataOmission::HardLinkTopology,
	MetadataOmission::SparseAllocation,
	MetadataOmission::InodeChangeTime,
];
const METADATA_OMISSION_COUNT: u64 = 4;

/// A scope outside the Linux basic metadata fidelity profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataOmission {
	/// Extended attributes outside the adapter's observable namespaces.
	HiddenExtendedAttributes,
	/// Relationships to other names that link to the source inode.
	HardLinkTopology,
	/// Physical allocation of sparse extents.
	SparseAllocation,
	/// The inode change time assigned by the filesystem.
	InodeChangeTime,
}

impl MetadataOmission {
	const fn code(self) -> u64 {
		match self {
			Self::HiddenExtendedAttributes => 1,
			Self::HardLinkTopology => 2,
			Self::SparseAllocation => 3,
			Self::InodeChangeTime => 4,
		}
	}
}

/// Read-back values for the metadata this journal profile preserves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BasicMetadata {
	mode: u32,
	/// Native user ID.
	pub uid: u32,
	/// Native group ID.
	pub gid: u32,
	/// Preserved access time.
	pub accessed_at: OwnerTimestamp,
	/// Preserved content modification time.
	pub modified_at: OwnerTimestamp,
}

impl BasicMetadata {
	/// Constructs a descriptor within the ordinary-permission profile.
	///
	/// # Errors
	/// Rejects any mode bits outside ordinary owner, group and other permissions.
	pub const fn new(
		mode: u32,
		uid: u32,
		gid: u32,
		accessed_at: OwnerTimestamp,
		modified_at: OwnerTimestamp,
	) -> Result<Self, VerificationRecordError> {
		if mode & !ORDINARY_PERMISSION_MASK != 0 {
			return Err(VerificationRecordError::UnsupportedMode);
		}
		Ok(Self {
			mode,
			uid,
			gid,
			accessed_at,
			modified_at,
		})
	}

	/// Ordinary Unix permission bits.
	#[must_use]
	pub const fn mode(&self) -> u32 {
		self.mode
	}
}

/// A local kind-6 observation after successful required metadata read-back and flush.
///
/// This profile requires the adapter's visible extended attribute checks. Hidden
/// attributes, hard-link topology, sparse allocation and inode change time remain
/// outside the recorded fidelity scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataRecorded {
	/// Job and plan context.
	pub context: JournalContext,
	/// The observed entry.
	pub entry: JournalEntryId,
	/// Native identity of the stage to which these values apply.
	pub stage: LinuxFileIdentity,
	/// Exact metadata values observed after application.
	pub metadata: BasicMetadata,
}

impl MetadataRecorded {
	/// Returns the explicit omissions required by the local profile.
	#[must_use]
	pub const fn omissions(&self) -> [MetadataOmission; 4] {
		METADATA_OMISSIONS
	}

	/// Encodes the local deterministic CBOR payload, excluding framing.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		encode_record(&self.context, self.entry, |encoder| {
			encoder
				.map(4)?
				.u64(0)?
				.u64(LINUX_BASIC_METADATA)?
				.u64(1)?
				.map(6)?
				.u64(0)?;
			write_identity(encoder, self.stage)?;
			encoder
				.u64(1)?
				.u32(self.metadata.mode())?
				.u64(2)?
				.u32(self.metadata.uid)?
				.u64(3)?
				.u32(self.metadata.gid)?
				.u64(4)?;
			write_timestamp(encoder, self.metadata.accessed_at)?;
			encoder.u64(5)?;
			write_timestamp(encoder, self.metadata.modified_at)?;
			encoder.u64(2)?.array(METADATA_OMISSION_COUNT)?;
			for omission in self.omissions() {
				encoder.u64(omission.code())?;
			}
			encoder.u64(3)?.u64(METADATA_BARRIER_COMPLETED)?;
			Ok(())
		})
	}

	/// Decodes a complete local deterministic CBOR kind-6 payload.
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
		decode_frame(frame, FrameKind::MetadataRecorded, Self::decode)
	}

	fn read_body(
		decoder: &mut Decoder<'_>,
		context: JournalContext,
		entry: JournalEntryId,
	) -> Result<Self, VerificationRecordError> {
		expect_map(decoder, 4)?;
		expect_key(decoder, 0)?;
		expect_evidence(decoder, LINUX_BASIC_METADATA)?;
		expect_key(decoder, 1)?;
		expect_map(decoder, 6)?;
		expect_key(decoder, 0)?;
		let stage = read_identity(decoder)?;
		expect_key(decoder, 1)?;
		let mode =
			u32::try_from(decoder.u64()?).map_err(|_| VerificationRecordError::UnsupportedMode)?;
		expect_key(decoder, 2)?;
		let uid = read_principal(decoder)?;
		expect_key(decoder, 3)?;
		let gid = read_principal(decoder)?;
		expect_key(decoder, 4)?;
		let accessed_at = read_timestamp(decoder)?;
		expect_key(decoder, 5)?;
		let modified_at = read_timestamp(decoder)?;
		let metadata = BasicMetadata::new(mode, uid, gid, accessed_at, modified_at)?;
		expect_key(decoder, 2)?;
		expect_array(decoder, METADATA_OMISSION_COUNT)?;
		for omission in METADATA_OMISSIONS {
			expect_evidence(decoder, omission.code())?;
		}
		expect_key(decoder, 3)?;
		expect_evidence(decoder, METADATA_BARRIER_COMPLETED)?;
		Ok(Self {
			context,
			entry,
			stage,
			metadata,
		})
	}
}

fn read_principal(decoder: &mut Decoder<'_>) -> Result<u32, VerificationRecordError> {
	u32::try_from(decoder.u64()?).map_err(|_| VerificationRecordError::InvalidPrincipal)
}

fn write_timestamp(
	encoder: &mut PayloadEncoder,
	timestamp: OwnerTimestamp,
) -> Result<(), PayloadWriteError> {
	encoder
		.map(2)?
		.u64(0)?
		.i64(timestamp.seconds())?
		.u64(1)?
		.u32(timestamp.nanoseconds())?;
	Ok(())
}

fn read_timestamp(decoder: &mut Decoder<'_>) -> Result<OwnerTimestamp, VerificationRecordError> {
	expect_map(decoder, 2)?;
	expect_key(decoder, 0)?;
	let seconds = decoder.i64()?;
	expect_key(decoder, 1)?;
	let nanos =
		u32::try_from(decoder.u64()?).map_err(|_| VerificationRecordError::InvalidTimestamp)?;
	OwnerTimestamp::new(seconds, nanos).map_err(|_| VerificationRecordError::InvalidTimestamp)
}
