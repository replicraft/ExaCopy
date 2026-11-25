use super::super::ManagedObjectIdentity;

#[derive(Debug)]
pub(super) struct PublicationObservation {
	pub(super) target: ManagedObjectIdentity,
	pub(super) stage_directory: ManagedObjectIdentity,
	pub(super) destination_directory: ManagedObjectIdentity,
}

/// Observations from an exclusive rename with both requested directory synchronizations.
///
/// The former private name was absent and the target matched the held, metadata-ready
/// inode. Both held directories passed `fsync` and the scoped thread policy was restored.
#[derive(Debug)]
pub struct PublishedFile(PublicationObservation);

impl PublishedFile {
	pub(super) const fn new(observation: PublicationObservation) -> Self {
		Self(observation)
	}

	/// Returns the native identity observed at the public target name.
	#[must_use]
	pub const fn target_identity(&self) -> ManagedObjectIdentity {
		self.0.target
	}

	/// Returns the identity of the synchronized directory that held the private stage.
	#[must_use]
	pub const fn synced_stage_directory(&self) -> ManagedObjectIdentity {
		self.0.stage_directory
	}

	/// Returns the identity of the synchronized directory that now holds the target.
	#[must_use]
	pub const fn synced_destination_directory(&self) -> ManagedObjectIdentity {
		self.0.destination_directory
	}
}
