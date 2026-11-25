//! Authenticates held private job history and verifies opt-in stage read-back.

use ed25519_dalek::VerifyingKey;
use exacopy_content::ContentDigest;
use exacopy_journal::{DarwinReceiptDigest, OwnerProfileId, RootCapabilityId};

mod capabilities;
mod protocol;
mod readback;

pub use capabilities::{
	InspectionInventory, InspectionJob, InspectionRecord, InspectionStageReader, ObservationError,
	StageMetadata, StageObservation,
};
pub use protocol::{Inspection, ProtocolError, RecordKind};
pub use readback::ReadBackError;

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

/// Authenticates private records and revalidates the held inventory and journal.
/// # Errors
/// Refuses unsafe artifacts, changed observations, and incompatible or untrusted records.
pub fn inspect<J: InspectionJob>(
	job: &J,
	authority: DarwinInspectionAuthority<'_>,
) -> Result<Inspection<J::Snapshot>, ProtocolError<J::Error>> {
	protocol::inspect(job, authority, protocol::NamespaceOnly).map(|(inspection, ())| inspection)
}

/// Authenticated namespace and digest from a selected private stage read-back.
pub type StageReadBackResult<S, E> = Result<(Inspection<S>, ContentDigest), ProtocolError<E>>;

/// Authenticates the job and independently measures its retained private stage.
/// # Errors
/// Refuses the same inconsistencies as [inspect] and any unsupported or changed stage evidence.
pub fn inspect_with_stage_read_back<J: InspectionJob>(
	job: &J,
	authority: DarwinInspectionAuthority<'_>,
	scratch: &mut [u8],
) -> StageReadBackResult<J::Snapshot, J::Error> {
	protocol::inspect(job, authority, protocol::StageReadBack(scratch))
}
