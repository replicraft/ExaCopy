//! Public Plan time, budgets and source-view evidence fields.

use minicbor::{Decoder, Encoder};
use uuid::Uuid;

use crate::cbor::{BodyBytes, EncodeError};
use crate::document::{expect_key, expect_map, fixed_bytes};
use crate::plan_identity::{PlanSourceIdentity, read_identity, write_identity};

use super::wire::{expect_array, read_nullable, read_uuid};
use super::{PlanError, PlanViewConsistency, check_label};

const NANOS_PER_SECOND: u32 = 1_000_000_000;
const MAX_INFLIGHT_IO: u8 = 64;

/// A normalized binary UTC timestamp with signed Unix seconds.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct UnixTimestamp {
	seconds: i64,
	nanoseconds: u32,
}

impl UnixTimestamp {
	/// Validates a signed seconds and fractional nanoseconds pair.
	///
	/// # Errors
	/// The fraction must be in the range 0 through 999,999,999.
	pub const fn new(seconds: i64, nanoseconds: u32) -> Result<Self, PlanError> {
		if nanoseconds >= NANOS_PER_SECOND {
			return Err(PlanError::Bounds);
		}
		Ok(Self {
			seconds,
			nanoseconds,
		})
	}

	/// Returns signed Unix seconds.
	#[must_use]
	pub const fn seconds(self) -> i64 {
		self.seconds
	}

	/// Returns normalized fractional nanoseconds.
	#[must_use]
	pub const fn nanoseconds(self) -> u32 {
		self.nanoseconds
	}

	pub(super) fn read_from(decoder: &mut Decoder<'_>) -> Result<Self, PlanError> {
		expect_array(decoder, 2)?;
		Self::new(decoder.i64()?, decoder.u32()?)
	}

	pub(super) fn write_to(self, encoder: &mut Encoder<BodyBytes>) -> Result<(), EncodeError> {
		encoder.array(2)?.i64(self.seconds)?.u32(self.nanoseconds)?;
		Ok(())
	}

	pub(super) fn write_optional(
		value: Option<Self>,
		encoder: &mut Encoder<BodyBytes>,
	) -> Result<(), EncodeError> {
		match value {
			Some(value) => value.write_to(encoder),
			None => {
				encoder.null()?;
				Ok(())
			}
		}
	}
}

/// The memory and in-flight I/O limits requested by a public Plan.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PlanResourceLimits {
	buffer_budget_bytes: u64,
	io_inflight_max: u8,
}

impl PlanResourceLimits {
	/// Validates a budget and a maximum in-flight I/O count.
	///
	/// # Errors
	/// The I/O count must be in the range 1 through 64.
	pub const fn new(buffer_budget_bytes: u64, io_inflight_max: u8) -> Result<Self, PlanError> {
		if io_inflight_max == 0 || io_inflight_max > MAX_INFLIGHT_IO {
			return Err(PlanError::Bounds);
		}
		Ok(Self {
			buffer_budget_bytes,
			io_inflight_max,
		})
	}

	/// Returns the requested buffer budget as bytes.
	#[must_use]
	pub const fn buffer_budget_bytes(self) -> u64 {
		self.buffer_budget_bytes
	}

	/// Returns the maximum in-flight I/O count.
	#[must_use]
	pub const fn io_inflight_max(self) -> u8 {
		self.io_inflight_max
	}

	pub(super) fn read_from(decoder: &mut Decoder<'_>) -> Result<Self, PlanError> {
		expect_map(decoder, 2)?;
		expect_key(decoder, 0)?;
		let buffer_budget_bytes = decoder.u64()?;
		expect_key(decoder, 1)?;
		Self::new(buffer_budget_bytes, decoder.u8()?)
	}

	pub(super) fn write_to(self, encoder: &mut Encoder<BodyBytes>) -> Result<(), EncodeError> {
		encoder
			.map(2)?
			.u8(0)?
			.u64(self.buffer_budget_bytes)?
			.u8(1)?
			.u8(self.io_inflight_max)?;
		Ok(())
	}
}

/// A source-view descriptor carried by the Plan body.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PlanSourceView<'body> {
	/// Opaque ID of the observed view.
	pub view_id: Uuid,
	/// Opaque root ID the caller must bind separately.
	pub root_id: Uuid,
	/// Observed consistency level.
	pub consistency: PlanViewConsistency,
	/// Provider name as Unicode text.
	pub provider: &'body str,
	/// Opaque ID of the associated measurement.
	pub measurement_id: Uuid,
	/// Optional opaque native identity.
	pub source_identity: Option<PlanSourceIdentity<'body>>,
	/// Normalized observation time.
	pub observed_at: UnixTimestamp,
	/// Optional digest of a snapshot token.
	pub snapshot_token_digest: Option<[u8; 32]>,
	/// Advisory stability expiry if supplied.
	pub stable_until: Option<UnixTimestamp>,
}

impl<'body> PlanSourceView<'body> {
	pub(super) fn read_from(decoder: &mut Decoder<'body>) -> Result<Self, PlanError> {
		expect_map(decoder, 9)?;
		expect_key(decoder, 0)?;
		let view_id = read_uuid(decoder)?;
		expect_key(decoder, 1)?;
		let root_id = read_uuid(decoder)?;
		expect_key(decoder, 2)?;
		let consistency = PlanViewConsistency::read(decoder)?;
		expect_key(decoder, 3)?;
		let provider = decoder.str()?;
		check_label(provider)?;
		expect_key(decoder, 4)?;
		let measurement_id = read_uuid(decoder)?;
		expect_key(decoder, 5)?;
		let source_identity = read_identity(decoder)?;
		expect_key(decoder, 6)?;
		let observed_at = UnixTimestamp::read_from(decoder)?;
		expect_key(decoder, 7)?;
		let snapshot_token_digest = read_nullable(decoder, |decoder| Ok(fixed_bytes(decoder)?))?;
		expect_key(decoder, 8)?;
		let stable_until = read_nullable(decoder, UnixTimestamp::read_from)?;
		Ok(Self {
			view_id,
			root_id,
			consistency,
			provider,
			measurement_id,
			source_identity,
			observed_at,
			snapshot_token_digest,
			stable_until,
		})
	}

	pub(super) fn write_to(self, encoder: &mut Encoder<BodyBytes>) -> Result<(), EncodeError> {
		encoder
			.map(9)?
			.u8(0)?
			.bytes(self.view_id.as_bytes())?
			.u8(1)?
			.bytes(self.root_id.as_bytes())?
			.u8(2)?
			.u8(self.consistency as u8)?
			.u8(3)?
			.str(self.provider)?
			.u8(4)?
			.bytes(self.measurement_id.as_bytes())?
			.u8(5)?;
		write_identity(encoder, self.source_identity)?;
		encoder.u8(6)?;
		self.observed_at.write_to(encoder)?;
		encoder.u8(7)?;
		match self.snapshot_token_digest {
			Some(digest) => encoder.bytes(&digest)?,
			None => encoder.null()?,
		};
		encoder.u8(8)?;
		UnixTimestamp::write_optional(self.stable_until, encoder)
	}
}
