use std::io::Read;

use exacopy_endpoint::UnixComponent;
use exacopy_journal::{DarwinFileIdentity, JournalJobId, OwnerError};

/// A job held under its current private and destination leases.
pub trait InspectionJob {
	/// The adapter failure retained for diagnostics.
	type Error;
	/// The checked namespace evidence returned to the coordinator.
	type Snapshot;
	/// A private readable record borrowing its held authority.
	type Record<'job>: InspectionRecord<Error = Self::Error>
	where
		Self: 'job;
	/// A destination and private stage inventory borrowing the job lease.
	type Inventory<'job>: InspectionInventory<Error = Self::Error, Snapshot = Self::Snapshot>
	where
		Self: 'job;

	/// Checks the private name against the journal job identity.
	fn matches_job(&self, expected: JournalJobId) -> bool;
	/// Returns the bound private job directory identity.
	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError>;
	/// Returns the observed owner of the private job.
	fn owner_uid(&self) -> u32;
	/// Revalidates the held destination and returns its identity.
	fn observe_destination(&self) -> Result<DarwinFileIdentity, ObservationError<Self::Error>>;
	/// Opens the canonical plan beneath the held private job.
	fn open_plan(&self) -> Result<Self::Record<'_>, Self::Error>;
	/// Opens the signed owner envelope beneath the held private job.
	fn open_owner(&self) -> Result<Self::Record<'_>, Self::Error>;
	/// Opens the leased first journal segment.
	fn open_first_segment(&self) -> Result<Self::Record<'_>, Self::Error>;
	/// Opens the fixed receipt or confirms its absence.
	fn open_receipt(&self) -> Result<Option<Self::Record<'_>>, Self::Error>;
	/// Observes the selected names without opening public target content.
	fn inventory<'job>(
		&'job self,
		stage: UnixComponent<'job>,
		target: UnixComponent<'job>,
	) -> Result<Self::Inventory<'job>, Self::Error>;
}

/// Failure to establish a journal-compatible live observation.
#[derive(Debug)]
pub enum ObservationError<E> {
	/// The adapter could not establish the required observation.
	Platform(E),
	/// The observed identity is outside the journal's representation.
	Identity(OwnerError),
}

/// A bounded readable record that can revalidate its held identity and name.
pub trait InspectionRecord: Read {
	/// The adapter failure retained for diagnostics.
	type Error;

	/// Returns the captured logical length.
	fn length(&self) -> u64;
	/// Rechecks the binding of the held observation.
	fn revalidate(&self) -> Result<(), Self::Error>;
}

/// A leased snapshot of the selected stage and target names with no publication authority.
pub trait InspectionInventory {
	/// The adapter failure retained for diagnostics.
	type Error;
	/// The checked namespace evidence returned to the coordinator.
	type Snapshot;
	/// A private stage observation suitable for an identity-bound read-only reopen.
	type Stage;
	/// The private stage reader borrowing the held inventory.
	type Reader<'inventory>: InspectionStageReader<Error = Self::Error>
	where
		Self: 'inventory;

	/// The maximum supported positioned read in bytes.
	const MAX_READ_BYTES: usize;

	/// Returns the inventory's checked stage directory identity.
	fn stage_directory_identity(&self) -> Option<DarwinFileIdentity>;
	/// Returns the checked occupied private stage and its extent.
	fn stage(&self) -> Option<StageObservation<Self::Stage>>;
	/// Opens the exact private stage recorded by the held inventory.
	fn open_stage_read_back(&self, stage: Self::Stage) -> Result<Self::Reader<'_>, Self::Error>;
	/// Rechecks the binding of the held observation.
	fn revalidate(&self) -> Result<(), Self::Error>;
	/// Returns the observed namespace facts for the caller.
	fn snapshot(&self) -> Self::Snapshot;
}

/// The exact held stage and its comparison facts in the journal's identity profile.
#[derive(Debug)]
pub struct StageObservation<S> {
	/// The held observation used for private read-back.
	pub held: S,
	/// The observed file identity in the journal profile.
	pub identity: DarwinFileIdentity,
	/// The logical length of the unnamed stream in bytes.
	pub length: u64,
}

/// An independently opened, read-only view of the verified private stage.
pub trait InspectionStageReader {
	/// The adapter failure retained for diagnostics.
	type Error;

	/// Returns metadata observed before the first content read.
	fn initial_metadata(&self) -> StageMetadata;
	/// Reads the exact bounded range from the held private stage.
	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error>;
	/// Rechecks the name, identity, complete extent and logical EOF.
	fn revalidate(&self) -> Result<StageMetadata, Self::Error>;
}

/// Required basic metadata facts observed on the private stage.
#[derive(Debug)]
pub struct StageMetadata {
	/// The observed owner identifier.
	pub uid: u32,
	/// The observed group identifier.
	pub gid: u32,
	/// The observed permission bits.
	pub mode: u32,
	/// Access time as seconds and nanoseconds from the Unix epoch.
	pub atime: (i64, u32),
	/// Modification time as seconds and nanoseconds from the Unix epoch.
	pub mtime: (i64, u32),
}
