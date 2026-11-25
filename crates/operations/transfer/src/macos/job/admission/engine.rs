use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	DarwinFileIdentity, DarwinRootBinding, ObservedTimestamp, OwnerError, RootCapabilityId,
};

use crate::macos::plan::{DestinationPlanBinding, SourcePlanBinding};

pub(super) enum AdmissionFailure<E> {
	Mismatch,
	Identity(OwnerError),
	Adapter(E),
}

pub(super) struct SourceIdentities {
	pub(super) root: DarwinFileIdentity,
	pub(super) file: DarwinFileIdentity,
}

#[derive(PartialEq, Eq)]
pub(super) struct Timestamp {
	pub(super) seconds: i64,
	pub(super) nanoseconds: u32,
}

impl From<ObservedTimestamp> for Timestamp {
	fn from(time: ObservedTimestamp) -> Self {
		Self {
			seconds: time.seconds(),
			nanoseconds: time.nanoseconds(),
		}
	}
}

pub(super) struct SourceMetadataObservation {
	pub(super) uid: u32,
	pub(super) gid: u32,
	pub(super) mode: u32,
	pub(super) accessed: Timestamp,
	pub(super) modified: Timestamp,
}

/// A held, read-only source selected under an independently authorized root.
pub(super) trait ReadOnlySource {
	type Error;

	fn component(&self) -> UnixComponent<'_>;
	fn length(&self) -> u64;
	fn observe_identities(&self) -> Result<SourceIdentities, AdmissionFailure<Self::Error>>;
	fn check_pre_read_metadata(&self) -> Result<SourceMetadataObservation, Self::Error>;
	fn change_time(&self) -> Result<Timestamp, Self::Error>;
}

pub(super) fn bind_destination<E>(
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

pub(super) fn check_source<S: ReadOnlySource>(
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
