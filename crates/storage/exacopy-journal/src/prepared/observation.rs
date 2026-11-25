use exacopy_endpoint::MAX_FILE_LENGTH;
use minicbor::encode::{self, Write};
use minicbor::{Decoder, Encoder};

use super::PreparedError;
use super::wire::{expect_array, expect_key, expect_map, read_identity, write_identity};
use crate::LinuxFileIdentity;

// The source consistency enum starts with live_observed (FIELD_REGISTRY).
const LIVE_OBSERVED: u64 = 0;
// Local v1 records that the adapter saw no visible extended attributes.
const NO_VISIBLE_EXTENDED_ATTRIBUTES: u64 = 0;

/// Opaque RFC UUID allocated to the held destination-root capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RootCapabilityId([u8; 16]);

impl RootCapabilityId {
	/// Validates the RFC variant and assigned UUID version in network order.
	///
	/// # Errors
	/// Returns an invalid root error for bytes outside the RFC UUID profile.
	pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, PreparedError> {
		if bytes[8] >> 6 != 0b10 || !matches!(bytes[6] >> 4, 1..=8) {
			return Err(PreparedError::InvalidRoot);
		}
		Ok(Self(bytes))
	}

	/// Returns this identifier in network byte order.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}
}

/// The destination-root capability and native identity bound by one job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DestinationRootBinding {
	/// Opaque UUID also stored in the entry's root-relative target path.
	pub id: RootCapabilityId,
	/// Device and inode observed through the destination directory handle.
	pub identity: LinuxFileIdentity,
}

/// A Linux observation time encoded as signed Unix seconds and fractional nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedTimestamp {
	seconds: i64,
	nanoseconds: u32,
}

impl ObservedTimestamp {
	/// Constructs one normalized native timestamp.
	///
	/// # Errors
	/// Returns a timestamp error for a fraction of at least one second.
	pub fn new(seconds: i64, nanoseconds: u32) -> Result<Self, PreparedError> {
		if nanoseconds >= 1_000_000_000 {
			return Err(PreparedError::InvalidTimestamp);
		}
		Ok(Self {
			seconds,
			nanoseconds,
		})
	}

	/// Returns the whole Unix seconds.
	#[must_use]
	pub const fn seconds(self) -> i64 {
		self.seconds
	}

	/// Returns the nanosecond fraction.
	#[must_use]
	pub const fn nanoseconds(self) -> u32 {
		self.nanoseconds
	}
}

/// The three native observation times available from the held Linux source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTimes {
	/// Access time observed before source data reads.
	pub accessed_at: ObservedTimestamp,
	/// Observed content modification time.
	pub modified_at: ObservedTimestamp,
	/// Observed inode change time.
	pub changed_at: ObservedTimestamp,
}

/// The bounded local v1 view of a live regular file held open for read-only copying.
///
/// The journal's local descriptor uses keys 0 consistency, 1 native identity,
/// 2 logical length, 3 atime, 4 mtime, and 5 ctime. Revalidation still needs the
/// live handle, and recovery must treat this evidence as a past observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveSourceView {
	identity: LinuxFileIdentity,
	length: u64,
	times: SourceTimes,
}

impl LiveSourceView {
	/// Wraps the observed native identity, extent, and inode times.
	///
	/// # Errors
	/// Returns a source length error if the logical length exceeds the local limit.
	pub fn new(
		identity: LinuxFileIdentity,
		length: u64,
		times: SourceTimes,
	) -> Result<Self, PreparedError> {
		if length > MAX_FILE_LENGTH {
			return Err(PreparedError::InvalidSourceLength);
		}
		Ok(Self {
			identity,
			length,
			times,
		})
	}

	/// Returns the observed native identity.
	#[must_use]
	pub const fn identity(self) -> LinuxFileIdentity {
		self.identity
	}

	/// Returns the observed unnamed-stream length.
	#[must_use]
	pub const fn length(self) -> u64 {
		self.length
	}

	/// Returns the native inode times.
	#[must_use]
	pub const fn times(self) -> SourceTimes {
		self.times
	}
}

/// The local v1 source metadata observation with no visible extended attributes.
///
/// The native map uses keys 0 mode, 1 owner, 2 group, 3 link count, and
/// 4 extended attribute observation (code 0, none visible).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceInodeMetadata {
	mode: u32,
	owner: u32,
	group: u32,
	link_count: u64,
}

impl SourceInodeMetadata {
	/// Wraps the observed basic inode data after the extended attribute check.
	///
	/// # Errors
	/// Returns a mode error if mode includes bits other than permission and special bits.
	pub fn no_visible_extended_attributes(
		mode: u32,
		owner: u32,
		group: u32,
		link_count: u64,
	) -> Result<Self, PreparedError> {
		if mode & !0o7777 != 0 {
			return Err(PreparedError::InvalidMode);
		}
		Ok(Self {
			mode,
			owner,
			group,
			link_count,
		})
	}

	/// Returns the observed permission and special bits.
	#[must_use]
	pub const fn mode(self) -> u32 {
		self.mode
	}

	/// Returns the observed owner ID.
	#[must_use]
	pub const fn owner(self) -> u32 {
		self.owner
	}

	/// Returns the observed group ID.
	#[must_use]
	pub const fn group(self) -> u32 {
		self.group
	}

	/// Returns the observed inode link count.
	#[must_use]
	pub const fn link_count(self) -> u64 {
		self.link_count
	}
}

pub(super) fn write_source<W: Write>(
	encoder: &mut Encoder<W>,
	source: LiveSourceView,
) -> Result<(), encode::Error<W::Error>> {
	encoder.map(6)?.u8(0)?.u64(LIVE_OBSERVED)?.u8(1)?;
	write_identity(encoder, source.identity)?;
	encoder.u8(2)?.u64(source.length)?.u8(3)?;
	write_timestamp(encoder, source.times.accessed_at)?;
	encoder.u8(4)?;
	write_timestamp(encoder, source.times.modified_at)?;
	encoder.u8(5)?;
	write_timestamp(encoder, source.times.changed_at)
}

pub(super) fn read_source(decoder: &mut Decoder<'_>) -> Result<LiveSourceView, PreparedError> {
	expect_map(decoder, 6)?;
	expect_key(decoder, 0)?;
	if decoder.u64()? != LIVE_OBSERVED {
		return Err(PreparedError::UnsupportedSourceView);
	}
	expect_key(decoder, 1)?;
	let identity = read_identity(decoder)?;
	expect_key(decoder, 2)?;
	let length = decoder.u64()?;
	expect_key(decoder, 3)?;
	let accessed_at = read_timestamp(decoder)?;
	expect_key(decoder, 4)?;
	let modified_at = read_timestamp(decoder)?;
	expect_key(decoder, 5)?;
	let changed_at = read_timestamp(decoder)?;
	LiveSourceView::new(
		identity,
		length,
		SourceTimes {
			accessed_at,
			modified_at,
			changed_at,
		},
	)
}

pub(super) fn write_source_metadata<W: Write>(
	encoder: &mut Encoder<W>,
	metadata: SourceInodeMetadata,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.map(5)?
		.u8(0)?
		.u32(metadata.mode)?
		.u8(1)?
		.u32(metadata.owner)?
		.u8(2)?
		.u32(metadata.group)?
		.u8(3)?
		.u64(metadata.link_count)?
		.u8(4)?
		.u64(NO_VISIBLE_EXTENDED_ATTRIBUTES)?;
	Ok(())
}

pub(super) fn read_source_metadata(
	decoder: &mut Decoder<'_>,
) -> Result<SourceInodeMetadata, PreparedError> {
	expect_map(decoder, 5)?;
	expect_key(decoder, 0)?;
	let mode = decoder.u32()?;
	expect_key(decoder, 1)?;
	let owner = decoder.u32()?;
	expect_key(decoder, 2)?;
	let group = decoder.u32()?;
	expect_key(decoder, 3)?;
	let link_count = decoder.u64()?;
	expect_key(decoder, 4)?;
	if decoder.u64()? != NO_VISIBLE_EXTENDED_ATTRIBUTES {
		return Err(PreparedError::UnsupportedSourceMetadata);
	}
	SourceInodeMetadata::no_visible_extended_attributes(mode, owner, group, link_count)
}

fn write_timestamp<W: Write>(
	encoder: &mut Encoder<W>,
	timestamp: ObservedTimestamp,
) -> Result<(), encode::Error<W::Error>> {
	encoder
		.array(2)?
		.i64(timestamp.seconds)?
		.u32(timestamp.nanoseconds)?;
	Ok(())
}

fn read_timestamp(decoder: &mut Decoder<'_>) -> Result<ObservedTimestamp, PreparedError> {
	expect_array(decoder, 2)?;
	ObservedTimestamp::new(decoder.i64()?, decoder.u32()?)
}
