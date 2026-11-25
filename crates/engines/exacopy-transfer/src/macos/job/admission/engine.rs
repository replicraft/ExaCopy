use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	DarwinFileIdentity, DarwinRootBinding, ObservedTimestamp, OwnerError, RootCapabilityId,
};

use crate::macos::plan::{DestinationPlanBinding, SourcePlanBinding};

/// A mismatch or observation failure that prevented plan admission.
#[derive(Debug)]
pub enum AdmissionFailure<E> {
	/// The live or independently supplied facts differ from the plan.
	Mismatch,
	/// The observed identity is outside the journal's representation.
	Identity(OwnerError),
	/// The adapter failed the requested operation.
	Adapter(E),
}

/// The held root and file bound to the selected source name.
#[derive(Debug)]
pub struct SourceIdentities {
	/// The revalidated source parent identity.
	pub root: DarwinFileIdentity,
	/// The revalidated source file identity.
	pub file: DarwinFileIdentity,
}

#[derive(Debug, PartialEq, Eq)]
/// Timestamp components reported by the held source.
pub struct Timestamp {
	/// Whole seconds relative to the Unix epoch.
	pub seconds: i64,
	/// Elapsed nanoseconds within the second.
	pub nanoseconds: u32,
}

impl From<ObservedTimestamp> for Timestamp {
	fn from(time: ObservedTimestamp) -> Self {
		Self {
			seconds: time.seconds(),
			nanoseconds: time.nanoseconds(),
		}
	}
}

/// The source's revalidated metadata after strict pre-read admission.
#[derive(Debug)]
pub struct SourceMetadataObservation {
	/// The observed owner identifier.
	pub uid: u32,
	/// The observed group identifier.
	pub gid: u32,
	/// The observed permission bits.
	pub mode: u32,
	/// The observed last access time.
	pub accessed: Timestamp,
	/// The observed last modification time.
	pub modified: Timestamp,
}

/// A held, read-only source selected under an independently authorized root.
pub trait ReadOnlySource {
	/// The adapter failure retained for diagnostics.
	type Error;

	/// Returns the raw selected component under the held root.
	fn component(&self) -> UnixComponent<'_>;
	/// Returns the captured logical length.
	fn length(&self) -> u64;
	/// Revalidates the held source parent, selected name, and file.
	fn observe_identities(&self) -> Result<SourceIdentities, AdmissionFailure<Self::Error>>;
	/// Checks strict basic metadata before payload reads.
	fn check_pre_read_metadata(&self) -> Result<SourceMetadataObservation, Self::Error>;
	/// Revalidates and observes the source file's change time.
	fn change_time(&self) -> Result<Timestamp, Self::Error>;
}

/// Checks the independently held root and observes the selected public name absent.
/// # Errors
/// Refuses mismatched authority or inconclusive destination observations.
pub fn bind_destination<E>(
	planned: DestinationPlanBinding<'_>,
	root_id: RootCapabilityId,
	observe_empty: impl FnOnce(UnixComponent<'_>) -> Result<DarwinFileIdentity, AdmissionFailure<E>>,
) -> Result<DarwinRootBinding, AdmissionFailure<E>> {
	if root_id != planned.root_id {
		return Err(AdmissionFailure::Mismatch);
	}
	let identity = observe_empty(planned.component)?;
	if identity != planned.root_identity {
		return Err(AdmissionFailure::Mismatch);
	}
	Ok(DarwinRootBinding {
		id: root_id,
		identity,
	})
}

/// Checks the held source and strict basic metadata against the original plan.
/// # Errors
/// Refuses mismatched authority, changed objects or metadata, and incomplete observations.
pub fn check_source<S: ReadOnlySource>(
	planned: SourcePlanBinding<'_>,
	source: &S,
	root_id: RootCapabilityId,
) -> Result<(), AdmissionFailure<S::Error>> {
	if (root_id, source.component(), source.length())
		!= (planned.root_id, planned.component, planned.length)
	{
		return Err(AdmissionFailure::Mismatch);
	}
	let identities = source.observe_identities()?;
	if (identities.root, identities.file) != (planned.root_identity, planned.file_identity) {
		return Err(AdmissionFailure::Mismatch);
	}
	let live = source
		.check_pre_read_metadata()
		.map_err(AdmissionFailure::Adapter)?;
	let changed = source.change_time().map_err(AdmissionFailure::Adapter)?;
	let expected = planned.metadata;
	if (live.uid, live.gid, live.mode)
		!= (
			expected.uid().get(),
			expected.gid(),
			u32::from(expected.mode()),
		)
		|| live.accessed != Timestamp::from(expected.accessed_at())
		|| live.modified != Timestamp::from(expected.modified_at())
		|| changed != Timestamp::from(expected.changed_at())
	{
		return Err(AdmissionFailure::Mismatch);
	}
	Ok(())
}
