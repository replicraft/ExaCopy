//! Preparation and publication policy for a managed APFS copy job.

use std::fmt;

use ed25519_dalek::SigningKey;
use exacopy_journal::{OwnerError, OwnerProfileId, OwnerTimestamp, OwnerToken};

use super::plan::PlanAttempt;

pub mod admission;
pub mod bootstrap;
pub mod entry;

pub(super) const STAGE_PAYLOAD: &[u8] = b"payload";

/// The independently trusted local signing profile and this attempt's owner claims.
#[derive(Clone, Copy)]
pub struct DarwinJobProfile<'profile> {
	/// Profile ID selected from trusted local configuration.
	pub id: OwnerProfileId,
	/// The key selected from the same trusted configuration as the profile ID.
	pub signer: &'profile SigningKey,
	/// The creation timestamp chosen by the coordinator.
	pub created: OwnerTimestamp,
	/// A fresh cryptographically random token independent of the job and profile IDs.
	pub owner_token: OwnerToken,
}

impl fmt::Debug for DarwinJobProfile<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("DarwinJobProfile")
			.finish_non_exhaustive()
	}
}

/// The private artifact that an attempted preparation was operating on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JobPreparationStep {
	/// The signed owner envelope.
	OwnerRecord,
	/// The canonical copy plan.
	PlanRecord,
	/// The first segment's parent directory.
	JournalDirectory,
	/// The exclusively created first segment.
	FirstSegment,
}

/// The independently selected signing profile did not authorize this planned attempt.
#[derive(Debug)]
pub enum ProfileError {
	/// The selected profile ID differs from the plan.
	Mismatch,
	/// The owner token or signing key was refused.
	Owner(OwnerError),
}

/// Checks the independently selected profile, owner token, and signing key.
/// # Errors
/// Refuses a profile mismatch, reused owner token, or weak verifying key.
pub fn validate_profile(
	attempt: PlanAttempt,
	profile: DarwinJobProfile<'_>,
) -> Result<(), ProfileError> {
	if attempt.profile != profile.id {
		return Err(ProfileError::Mismatch);
	}
	if profile.owner_token.as_bytes() == attempt.job.as_bytes()
		|| profile.owner_token.as_bytes() == profile.id.as_bytes()
	{
		return Err(ProfileError::Owner(OwnerError::InvalidToken));
	}
	if profile.signer.verifying_key().is_weak() {
		return Err(ProfileError::Owner(OwnerError::InvalidSignature));
	}
	Ok(())
}
