//! Filesystem effects for writing one caller-validated public Plan bundle.

use crate::UnixComponent;

/// The result of attempting to create the page's name exclusively.
pub enum PageCreation<Record> {
	/// The adapter created, wrote, synchronized and checked the new record.
	Created(Record),
	/// The exact name was occupied. Its contents have not been admitted.
	Existing,
}

/// Effects supplied to the Plan bundle writer by a filesystem adapter.
///
/// The implementation fixes a bundle directory, output name, and protected
/// input scopes for the lifetime of the capability. Prefixes with incomplete
/// work are retained and failures never authorize replacement or cleanup.
pub trait PlanBundleSink {
	/// Opaque held pages directory.
	type Pages;
	/// Opaque held page or envelope record.
	type Record;
	/// Typed refusal or unsuccessful filesystem effect.
	type Error;

	/// Rechecks bundle identity, protection and disjointness.
	///
	/// # Errors
	/// Refuses changed, unsafe or overlapping scope.
	fn check_scope(&self) -> Result<(), Self::Error>;

	/// Observes current absence of the selected envelope name.
	///
	/// # Errors
	/// Refuses present or unavailable names.
	fn ensure_output_absent(&self) -> Result<(), Self::Error>;

	/// Opens or creates the protected pages directory relative to the bundle.
	///
	/// # Errors
	/// Refuses unavailable, unsafe or changed directory entries.
	fn open_pages(&self) -> Result<Self::Pages, Self::Error>;

	/// Creates one page exclusively and synchronizes and rechecks its file.
	///
	/// # Errors
	/// Reports failed open, write, barrier or name observations.
	fn create_page(
		&self,
		pages: &Self::Pages,
		name: UnixComponent<'_>,
		bytes: &[u8],
	) -> Result<PageCreation<Self::Record>, Self::Error>;

	/// Verifies an incumbent page using exact caller-sized read-back storage.
	///
	/// # Errors
	/// Refuses mismatching bytes, unsafe or changed identity and failed barriers.
	fn verify_existing_page(
		&self,
		pages: &Self::Pages,
		name: UnixComponent<'_>,
		bytes: &[u8],
		scratch: &mut [u8],
	) -> Result<Self::Record, Self::Error>;

	/// Rechecks the held pages directory against the current name.
	///
	/// # Errors
	/// Refuses unavailable, unsafe or changed identity.
	fn check_pages(&self, pages: &Self::Pages) -> Result<(), Self::Error>;

	/// Synchronizes the held pages directory.
	///
	/// # Errors
	/// Reports a directory barrier error.
	fn sync_pages(&self, pages: &Self::Pages) -> Result<(), Self::Error>;

	/// Synchronizes the held bundle directory.
	///
	/// # Errors
	/// Reports a directory barrier error.
	fn sync_bundle(&self) -> Result<(), Self::Error>;

	/// Verifies the page's held identity and current name.
	///
	/// # Errors
	/// Refuses an unavailable or changed observation.
	fn check_page(
		&self,
		pages: &Self::Pages,
		name: UnixComponent<'_>,
		page: &Self::Record,
	) -> Result<(), Self::Error>;

	/// Exclusively creates, writes, synchronizes and checks the envelope file.
	///
	/// A new final name can be visible before its write completes.
	///
	/// # Errors
	/// Refuses present names and reports failed write or barrier observations.
	fn create_output(&self, envelope: &[u8]) -> Result<Self::Record, Self::Error>;

	/// Verifies the envelope's held identity and current name.
	///
	/// # Errors
	/// Refuses an unavailable or changed observation.
	fn check_output(&self, output: &Self::Record) -> Result<(), Self::Error>;
}
