use std::fmt;

use exacopy_model::{InvalidJobId, JobId};

const JOB_PREFIX: &str = ".exacopy-";

/// A private namespace component derived solely from a validated RFC UUIDv7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobName {
	id: JobId,
	bytes: [u8; 16],
}

impl JobName {
	/// Validates a UUIDv7 and selects its canonical private job component.
	///
	/// # Errors
	/// Rejects an unsupported UUID version or variant.
	pub fn from_uuid_bytes(bytes: [u8; 16]) -> Result<Self, InvalidJobId> {
		let id = JobId::try_from_bytes(bytes)?;
		Ok(Self { id, bytes })
	}

	/// Returns the model identity used to derive this job name.
	#[must_use]
	pub const fn job_id(self) -> JobId {
		self.id
	}
}

impl fmt::Display for JobName {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let hex = format!("{:032x}", u128::from_be_bytes(self.bytes));
		write!(
			formatter,
			"{JOB_PREFIX}{}-{}-{}-{}-{}",
			&hex[..8],
			&hex[8..12],
			&hex[12..16],
			&hex[16..20],
			&hex[20..],
		)
	}
}
