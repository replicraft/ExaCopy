use minicbor::encode::write::{Cursor, EndOfArray};
use minicbor::{Decoder, Encoder, encode};

use super::wire::{read_job_header, read_root, write_header, write_root};
use super::{DarwinPreparedError, DarwinRootBinding};
use crate::frame::{Frame, FrameKind};
use crate::prepared::wire::{expect_key, expect_map, read_fixed};
use crate::{DarwinOwnerRecord, JournalContext, OwnerDigest, PlanDigest, PreparedError};

// Full-width common header, two digests, and one bounded native root binding.
const MAX_JOB_BYTES: usize = 256;
type JobCursor = Cursor<[u8; MAX_JOB_BYTES]>;

/// Managed APFS job preparation for journal kind 1.
///
/// Validating the exact signed owner also requires the independently selected
/// trusted profile and key. Reopening requires checking the live root capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinJobPrepared {
	context: JournalContext,
	owner_digest: OwnerDigest,
	destination_root: DarwinRootBinding,
}

impl DarwinJobPrepared {
	/// Binds the prepared job and destination to the exact signed owner bytes.
	///
	/// # Errors
	/// Returns an error if the signed owner, job context, or destination disagree.
	pub fn new(
		context: JournalContext,
		owner: &DarwinOwnerRecord,
		destination_root: DarwinRootBinding,
	) -> Result<Self, DarwinPreparedError> {
		let record = Self {
			context,
			owner_digest: owner.digest(),
			destination_root,
		};
		record.validate_owner(owner)?;
		Ok(record)
	}

	/// Checks the recorded job and plan against the supplied authenticated owner.
	///
	/// # Errors
	/// Rejects incorrect signed owner bytes, job or plan digest, unexpected volume,
	/// or a destination root that aliases the owner-private job directory.
	pub fn validate_owner(&self, owner: &DarwinOwnerRecord) -> Result<(), DarwinPreparedError> {
		let manifest = owner.manifest();
		if (manifest.job, manifest.plan_digest, owner.digest())
			!= (
				self.context.job,
				self.context.plan_digest,
				self.owner_digest,
			) {
			return Err(DarwinPreparedError::OwnerMismatch);
		}
		if manifest.destination_volume != self.destination_root.identity.volume() {
			return Err(DarwinPreparedError::VolumeMismatch);
		}
		if manifest
			.state_root
			.may_alias(self.destination_root.identity)
		{
			return Err(DarwinPreparedError::IdentityAlias);
		}
		Ok(())
	}

	/// Returns the job, epoch, and digest of the immutable canonical plan.
	#[must_use]
	pub const fn context(&self) -> JournalContext {
		self.context
	}

	/// Returns the digest of the exact signed owner bytes.
	#[must_use]
	pub const fn owner_digest(&self) -> OwnerDigest {
		self.owner_digest
	}

	/// Returns the destination root observed through the provisioned capability.
	#[must_use]
	pub const fn destination_root(&self) -> DarwinRootBinding {
		self.destination_root
	}

	/// Encodes the deterministic managed APFS payload.
	#[must_use]
	pub fn encode(&self) -> Vec<u8> {
		let canonical = self.encode_bounded();
		canonical.get_ref()[..canonical.position()].to_vec()
	}

	/// Decodes a complete, canonical, profile-specific kind-1 frame payload.
	///
	/// # Errors
	/// Refuses other kinds and invalid or unsupported payloads.
	pub fn from_frame(frame: &Frame) -> Result<Self, DarwinPreparedError> {
		if frame.kind() != FrameKind::JobPrepared {
			return Err(PreparedError::WrongRecordKind.into());
		}
		Self::decode(frame.payload())
	}

	/// Decodes a complete payload from an independently identified kind-1 frame.
	///
	/// # Errors
	/// Refuses malformed, oversized, noncanonical or unsupported payloads.
	pub fn decode(payload: &[u8]) -> Result<Self, DarwinPreparedError> {
		if payload.len() > MAX_JOB_BYTES {
			return Err(PreparedError::PayloadTooLarge.into());
		}
		let mut decoder = Decoder::new(payload);
		let context = read_job_header(&mut decoder)?;
		expect_map(&mut decoder, 3)?;
		expect_key(&mut decoder, 0)?;
		let owner_digest = OwnerDigest::from_bytes(read_fixed(&mut decoder)?);
		expect_key(&mut decoder, 1)?;
		let plan_reference = PlanDigest::from_bytes(read_fixed(&mut decoder)?);
		if plan_reference != context.plan_digest {
			return Err(PreparedError::PlanMismatch.into());
		}
		expect_key(&mut decoder, 2)?;
		let destination_root = read_root(&mut decoder)?;
		let record = Self {
			context,
			owner_digest,
			destination_root,
		};
		let canonical = record.encode_bounded();
		if canonical.get_ref()[..canonical.position()] != *payload {
			return Err(PreparedError::NonCanonical.into());
		}
		Ok(record)
	}

	fn encode_bounded(&self) -> JobCursor {
		let mut encoder = Encoder::new(Cursor::new([0; MAX_JOB_BYTES]));
		self.write_payload(&mut encoder)
			.expect("the fixed job fields fit their bounded buffer");
		encoder.into_writer()
	}

	fn write_payload(
		&self,
		encoder: &mut Encoder<JobCursor>,
	) -> Result<(), encode::Error<EndOfArray>> {
		write_header(encoder, self.context, None)?;
		encoder
			.map(3)?
			.u8(0)?
			.bytes(self.owner_digest.as_bytes())?
			.u8(1)?
			.bytes(self.context.plan_digest.as_bytes())?
			.u8(2)?;
		write_root(encoder, self.destination_root)
	}
}
