use exacopy_model::CopyBinding;

use super::super::ManagedObjectIdentity;

/// Expected original bindings passed to the final publication gate.
///
/// These are the bindings of the original held stage and destination. This
/// view carries no file handle, live authority or journal evidence.
#[derive(Clone, Copy, Debug)]
pub struct PublicationGateRequest<'name> {
	pub(super) binding: CopyBinding,
	pub(super) expected_stage: ManagedObjectIdentity,
	pub(super) expected_stage_directory: ManagedObjectIdentity,
	pub(super) expected_destination_directory: ManagedObjectIdentity,
	pub(super) expected_stage_name: &'name [u8],
	pub(super) expected_target_name: &'name [u8],
}

impl<'name> PublicationGateRequest<'name> {
	/// The exact model binding already consumed for this publication.
	#[must_use]
	pub const fn binding(self) -> CopyBinding {
		self.binding
	}

	/// The original held replacement inode's exact native identity.
	#[must_use]
	pub const fn expected_stage(self) -> ManagedObjectIdentity {
		self.expected_stage
	}

	/// Identity of the original held private stage directory.
	#[must_use]
	pub const fn expected_stage_directory(self) -> ManagedObjectIdentity {
		self.expected_stage_directory
	}

	/// Identity of the original held public destination directory.
	#[must_use]
	pub const fn expected_destination_directory(self) -> ManagedObjectIdentity {
		self.expected_destination_directory
	}

	/// Exact raw component of the original private stage.
	#[must_use]
	pub const fn expected_stage_name(self) -> &'name [u8] {
		self.expected_stage_name
	}

	/// Exact raw public component selected for exclusive placement.
	#[must_use]
	pub const fn expected_target_name(self) -> &'name [u8] {
		self.expected_target_name
	}
}

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
