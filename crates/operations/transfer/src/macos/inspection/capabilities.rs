use std::io::Read;

use exacopy_endpoint::UnixComponent;
use exacopy_journal::{DarwinFileIdentity, JournalJobId, OwnerError};

/// A job held under its current private and destination leases.
pub(super) trait InspectionJob {
	type Error;
	type Snapshot;
	type Record<'job>: InspectionRecord<Error = Self::Error>
	where
		Self: 'job;
	type Inventory<'job>: InspectionInventory<Error = Self::Error, Snapshot = Self::Snapshot>
	where
		Self: 'job;

	fn matches_job(&self, expected: JournalJobId) -> bool;
	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError>;
	fn owner_uid(&self) -> u32;
	fn observe_destination(&self) -> Result<DarwinFileIdentity, ObservationError<Self::Error>>;
	fn open_plan(&self) -> Result<Self::Record<'_>, Self::Error>;
	fn open_owner(&self) -> Result<Self::Record<'_>, Self::Error>;
	fn open_first_segment(&self) -> Result<Self::Record<'_>, Self::Error>;
	fn open_receipt(&self) -> Result<Option<Self::Record<'_>>, Self::Error>;
	fn inventory<'job>(
		&'job self,
		stage: UnixComponent<'job>,
		target: UnixComponent<'job>,
	) -> Result<Self::Inventory<'job>, Self::Error>;
}

pub(super) enum ObservationError<E> {
	Platform(E),
	Identity(OwnerError),
}

/// A bounded readable record that can revalidate its held identity and name.
pub(super) trait InspectionRecord: Read {
	type Error;

	fn length(&self) -> u64;
	fn revalidate(&self) -> Result<(), Self::Error>;
}

/// A leased snapshot of the selected stage and target names with no publication authority.
pub(super) trait InspectionInventory {
	type Error;
	type Snapshot;
	type Stage;
	type Reader<'inventory>: InspectionStageReader<Error = Self::Error>
	where
		Self: 'inventory;

	const MAX_READ_BYTES: usize;

	fn stage_directory_identity(&self) -> Option<DarwinFileIdentity>;
	fn stage(&self) -> Option<StageObservation<Self::Stage>>;
	fn open_stage_read_back(&self, stage: Self::Stage) -> Result<Self::Reader<'_>, Self::Error>;
	fn revalidate(&self) -> Result<(), Self::Error>;
	fn snapshot(&self) -> Self::Snapshot;
}

/// The exact held stage and its comparison facts in the journal's identity profile.
pub(super) struct StageObservation<S> {
	pub(super) held: S,
	pub(super) identity: DarwinFileIdentity,
	pub(super) length: u64,
}

/// An independently opened, read-only view of the verified private stage.
pub(super) trait InspectionStageReader {
	type Error;

	fn initial_metadata(&self) -> StageMetadata;
	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error>;
	/// Rechecks the name, identity, complete extent and logical EOF.
	fn revalidate(&self) -> Result<StageMetadata, Self::Error>;
}

pub(super) struct StageMetadata {
	pub(super) uid: u32,
	pub(super) gid: u32,
	pub(super) mode: u32,
	pub(super) atime: (i64, u32),
	pub(super) mtime: (i64, u32),
}
