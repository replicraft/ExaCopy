use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::wire::{
	expect_key, expect_map, read_fixed, read_identity, read_job_header, write_header,
	write_identity,
};
use super::{DestinationRootBinding, JournalContext, PreparedError, RootCapabilityId};
use crate::frame::{Frame, FrameKind};
use crate::{OwnerDigest, PlanDigest};

// Maximum-width epoch, UUIDv7, one digest and three map headers, plus the bound body.
const MAX_JOB_BYTES: usize = 192;
type JobCursor = Cursor<[u8; MAX_JOB_BYTES]>;

/// The local v1 job preparation observation for journal kind 1.
///
/// The plan reference is content-addressed by the canonical plan digest. The
/// destination-root binding records the capability UUID and the held directory's
/// native identity. A replay must verify these claims against the plan and owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobPrepared {
	/// The job, epoch, and canonical plan digest.
	pub context: JournalContext,
	/// The digest of the signed owner record's exact bytes.
	pub owner_digest: OwnerDigest,
	/// The destination root observed for this job.
	pub destination_root: DestinationRootBinding,
}

impl JobPrepared {
	/// Encodes a complete local v1 deterministic CBOR payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let canonical = self.encode_bounded();
		canonical.get_ref()[..canonical.position()].to_vec()
	}

	/// Checks the frame kind and decodes the canonical payload.
	///
	/// # Errors
	/// Returns a typed error for an incompatible kind or invalid payload.
	pub fn from_frame(frame: &Frame) -> Result<Self, PreparedError> {
		if frame.kind() != FrameKind::JobPrepared {
			return Err(PreparedError::WrongRecordKind);
		}
		Self::decode(frame.payload())
	}

	/// Decodes a complete payload from an independently identified kind-1 frame.
	///
	/// # Errors
	/// Returns a typed error for malformed or unsupported bytes.
	pub fn decode(payload: &[u8]) -> Result<Self, PreparedError> {
		if payload.len() > MAX_JOB_BYTES {
			return Err(PreparedError::PayloadTooLarge);
		}
		let mut decoder = Decoder::new(payload);
		let context = read_job_header(&mut decoder)?;
		expect_map(&mut decoder, 3)?;
		expect_key(&mut decoder, 0)?;
		let owner_digest = OwnerDigest::from_bytes(read_fixed(&mut decoder)?);
		expect_key(&mut decoder, 1)?;
		let plan_reference = PlanDigest::from_bytes(read_fixed(&mut decoder)?);
		if plan_reference != context.plan_digest {
			return Err(PreparedError::PlanMismatch);
		}
		expect_key(&mut decoder, 2)?;
		expect_map(&mut decoder, 2)?;
		expect_key(&mut decoder, 0)?;
		let id = RootCapabilityId::from_bytes(read_fixed(&mut decoder)?)?;
		expect_key(&mut decoder, 1)?;
		let identity = read_identity(&mut decoder)?;
		let record = Self {
			context,
			owner_digest,
			destination_root: DestinationRootBinding { id, identity },
		};
		let canonical = record.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(PreparedError::NonCanonical);
		}
		Ok(record)
	}

	fn encode_bounded(&self) -> JobCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_JOB_BYTES]));
		self.write_payload(&mut encoder)
			.expect("the validated job preparation payload fits its fixed-size buffer");
		encoder.into_writer()
	}

	fn write_payload(
		&self,
		encoder: &mut Encoder<JobCursor>,
	) -> Result<(), encode::Error<EndOfArray>> {
		write_header(encoder, &self.context, None)?;
		encoder
			.map(3)?
			.u8(0)?
			.bytes(self.owner_digest.as_bytes())?
			.u8(1)?
			.bytes(self.context.plan_digest.as_bytes())?
			.u8(2)?
			.map(2)?
			.u8(0)?
			.bytes(self.destination_root.id.as_bytes())?
			.u8(1)?;
		write_identity(encoder, self.destination_root.identity)
	}
}
