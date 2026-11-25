//! Read-only inspection of a private managed APFS copy job and its initial history.

use ed25519_dalek::VerifyingKey;
use exacopy_content::ContentDigest;
use exacopy_journal::{DarwinReceiptDigest, OwnerProfileId, RootCapabilityId};
use exacopy_platform::macos::ManagedObjectIdentity;
use exacopy_platform::macos::staging::jobs::{RecoveryFileObservation, RecoveryJob};

use super::replay::DarwinJournalReplay;

mod capabilities;
mod error;
mod native;
mod protocol;
mod readback;

pub use error::{DarwinInspectionError, DarwinStageReadBackError};

use protocol::{NamespaceOnly, StageReadBack};

/// Trust inputs independently supplied by the caller holding the recovered destination.
#[derive(Clone, Copy, Debug)]
pub struct DarwinInspectionAuthority<'key> {
	/// Profile selected from trusted local configuration.
	pub profile: OwnerProfileId,
	/// Verification key selected for that profile.
	pub key: &'key VerifyingKey,
	/// Capability identifier independently assigned to the held destination.
	pub destination_root: RootCapabilityId,
}

/// Receipt artifact observation under the job lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DarwinReceiptArtifact {
	/// The receipt directory or fixed receipt name was absent.
	Missing,
	/// A bounded private receipt exists without an accepted journal commitment.
	PresentUncommitted,
	/// The canonical artifact matches the accepted historical commitment.
	MatchesCommitment(DarwinReceiptDigest),
}

/// Authenticated initial history and freshly checked namespace observations.
#[derive(Debug)]
pub struct DarwinJobInspection {
	/// The canonical plan bytes authenticated by the signed owner.
	pub plan_bytes: Vec<u8>,
	/// The accepted prefix from the held first journal segment.
	pub replay: DarwinJournalReplay,
	/// The private receipt artifact observation, independent of live file content.
	pub receipt: DarwinReceiptArtifact,
	/// The observed private stage directory, if present.
	pub stage_directory: Option<ManagedObjectIdentity>,
	/// The observed private stage name, if occupied by a checked regular file.
	pub stage: Option<RecoveryFileObservation>,
	/// The observed public target name, if occupied by a checked regular file.
	pub target: Option<RecoveryFileObservation>,
}

/// Joins the native recovery inventory to the authenticated, read-only initial replay.
///
/// Reports current namespace observations and historical commitment under the held job
/// lease. The stage and target observations cover identity and extent.
///
/// # Errors
/// Refuses changed or unsafe artifacts, incompatible or unauthenticated history, and a
/// receipt that disagrees with an accepted commitment.
pub fn inspect_job(
	job: &RecoveryJob<'_>,
	authority: DarwinInspectionAuthority<'_>,
) -> Result<DarwinJobInspection, DarwinInspectionError> {
	protocol::inspect(job, authority, NamespaceOnly)
		.map(|(inspection, ())| inspection.into())
		.map_err(Into::into)
}

/// Checks the retained private stage against accepted historical verification.
///
/// This opt-in inspection can advance the stage's access time. If the replay
/// includes required metadata, it must match both before and after the reads.
/// The returned digest describes the private stage observed during this
/// inspection. Neither the source nor the public target is opened for content.
///
/// # Errors
/// Refuses missing verification, changed bindings, invalid scratch bounds,
/// ineligible stage metadata, I/O failures, and digest or recorded metadata mismatches.
pub fn inspect_job_with_stage_read_back(
	job: &RecoveryJob<'_>,
	authority: DarwinInspectionAuthority<'_>,
	scratch: &mut [u8],
) -> Result<(DarwinJobInspection, ContentDigest), DarwinInspectionError> {
	protocol::inspect(job, authority, StageReadBack(scratch))
		.map(|(inspection, digest)| (inspection.into(), digest))
		.map_err(Into::into)
}
