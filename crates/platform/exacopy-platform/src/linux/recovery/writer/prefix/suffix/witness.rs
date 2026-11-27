use std::ffi::OsStr;
use std::fs::File;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt as _;

use exacopy_endpoint::ReadView;
use rustix::fs::{self, AtFlags};

use super::{
	RetainedPrefixRead, RetainedPrefixSelection, RetainedSuffixReadback, RetainedSuffixWriter,
	SourceObservation, StageError, SuffixError, SyncedRetainedPrefix,
};

mod lane;
use crate::linux::WitnessReservationObservationError;
use crate::linux::handle::mount_id;
use crate::linux::recovery::{check_absent, open_path};
use crate::linux::stage::{check_no_visible_attributes, sync_directory};
pub use lane::WitnessCredentialLane;

/// A protected same-inode witness and the original private stage, after both barriers.
///
/// The original stage guard remains held. This read-only view grants no
/// metadata, rename or receipt authority.
#[must_use]
pub struct WitnessedSuffixReadback<'view, 'lease> {
	stage: WitnessLinkCandidate<'view, 'lease>,
	aliases: [File; 2],
	name: [u8; 40],
	stamp: SourceObservation,
}

/// Exact syscall presented to the live assembly gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtectedWitnessEffect {
	/// Exclusively link the original held inode into the protected job.
	Link,
	/// Sync the observed shared stage inode.
	FileBarrier,
	/// Sync the protected job directory containing the new witness.
	JobBarrier,
}

/// Whether the requested native witness could have affected the namespace.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProtectedWitnessError<E> {
	/// Original journal, lease, qualification or receipt could not be reaffirmed.
	Custody {
		/// Whether link submission had already started at this check.
		after_link: bool,
		/// Original custody error.
		cause: WitnessReservationObservationError,
	},
	/// The exact candidate failed a check before link submission.
	Preflight(StageError),
	/// The link was refused before submission.
	Admission(E),
	/// A link or subsequent barrier/observation could not be confirmed.
	Submitted(StageError),
	/// A later barrier was denied after link submission. The link stays in place.
	BarrierAdmission(E),
}

/// The original exact completed stage, opened on the checked unprivileged
/// foreground thread before admission to the witnessed kind-41 transition.
#[must_use]
pub struct WitnessLinkCandidate<'view, 'lease> {
	stage: RetainedSuffixReadback<'view, 'lease>,
	lane: WitnessCredentialLane,
}

impl<'view, 'lease> RetainedSuffixWriter<'view, 'lease> {
	/// Closes the writer and opens the independently checked stage on a witness lane.
	///
	/// # Errors
	/// Refuses a changed stage or an unsupported thread credential observation.
	pub fn finish_for_witness(
		self,
		lane: WitnessCredentialLane,
	) -> Result<WitnessLinkCandidate<'view, 'lease>, StageError> {
		lane.recheck()?;
		WitnessLinkCandidate::admit(self.finish()?, lane)
	}
}

impl<'view, 'lease> SyncedRetainedPrefix<'view, 'lease> {
	/// Opens the same admitted zero-tail stage on the exact witness lane.
	///
	/// # Errors
	/// Refuses a stale lane, mismatched stage/extent or failed continuation gate.
	pub fn zero_tail_for_witness<E>(
		self,
		source_end: u64,
		lane: WitnessCredentialLane,
		admit_continuation: impl FnOnce(RetainedPrefixSelection<'_>, Range<u64>) -> Result<(), E>,
	) -> Result<WitnessLinkCandidate<'view, 'lease>, SuffixError<E>> {
		lane.recheck().map_err(SuffixError::Observation)?;
		WitnessLinkCandidate::admit(
			self.zero_tail_readback(source_end, admit_continuation)?,
			lane,
		)
		.map_err(SuffixError::Observation)
	}
}

impl<'view, 'lease> WitnessLinkCandidate<'view, 'lease> {
	fn admit(
		stage: RetainedSuffixReadback<'view, 'lease>,
		lane: WitnessCredentialLane,
	) -> Result<Self, StageError> {
		let result = Self { stage, lane };
		result.recheck_observation()?;
		Ok(result)
	}
}

impl ReadView for WitnessLinkCandidate<'_, '_> {
	type Error = StageError;

	fn length(&self) -> u64 {
		self.stage.length()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.lane.recheck()?;
		self.stage.recheck_observation()?;
		let stamp = self.stage.file.observation();
		if stamp.group() != rustix::process::getegid().as_raw()
			|| stamp.owner() != rustix::process::geteuid().as_raw()
		{
			return Err(StageError::UnsafeFile);
		}
		self.lane.recheck()
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.stage.read_exact_at(offset, bytes)
	}
}

impl WitnessLinkCandidate<'_, '_> {
	/// Tests association with the original retained read guard.
	#[must_use]
	pub fn matches_reader(&self, reader: &RetainedPrefixRead<'_>) -> bool {
		std::ptr::eq(self.stage.reader, reader)
	}

	pub(in crate::linux::recovery::writer) fn check_for_witness(
		&self,
		reader: &RetainedPrefixRead<'_>,
		name: &[u8; 40],
	) -> Result<(), StageError> {
		if !std::ptr::eq(self.stage.reader, reader)
			|| !name.starts_with(b"witness.")
			|| !name[8..]
				.iter()
				.all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
		{
			return Err(StageError::IdentityChanged);
		}
		self.recheck_observation()?;
		check_absent(&reader.lease.job().directory.file, OsStr::from_bytes(name))?;
		self.recheck_observation()
	}
}

impl<'view, 'lease> WitnessLinkCandidate<'view, 'lease> {
	pub(in crate::linux::recovery::writer) fn link_checked_witness<G, E>(
		self,
		name: [u8; 40],
		mut enter: impl FnMut(ProtectedWitnessEffect) -> Result<G, ProtectedWitnessError<E>>,
	) -> Result<WitnessedSuffixReadback<'view, 'lease>, ProtectedWitnessError<E>> {
		use ProtectedWitnessError as Error;
		self.check_for_witness(self.stage.reader, &name)
			.map_err(Error::Preflight)?;
		let job = self.stage.reader.lease.job();
		let old = self.stage.file.observation();
		let guard = enter(ProtectedWitnessEffect::Link)?;
		let linked = fs::linkat(
			&self.stage.file.file,
			c"",
			&job.directory.file,
			OsStr::from_bytes(&name),
			AtFlags::EMPTY_PATH,
		);
		drop(guard);
		linked.map_err(|error| Error::Submitted(error.into()))?;

		let (stamp, aliases) = observe_two_names(&self.stage, &name).map_err(Error::Submitted)?;
		if !same_stage_after_link(old, stamp) {
			return Err(Error::Submitted(StageError::IdentityChanged));
		}
		let witnessed = WitnessedSuffixReadback {
			stage: self,
			aliases,
			name,
			stamp,
		};
		witnessed.recheck_observation().map_err(Error::Submitted)?;
		let guard = enter(ProtectedWitnessEffect::FileBarrier)?;
		let synced = fs::fsync(&witnessed.stage.stage.file.file);
		drop(guard);
		synced.map_err(|error| Error::Submitted(StageError::BarrierFailed(error.into())))?;

		witnessed.recheck_observation().map_err(Error::Submitted)?;
		let guard = enter(ProtectedWitnessEffect::JobBarrier)?;
		let synced = sync_directory(&witnessed.stage.stage.reader.lease.lock);
		drop(guard);
		synced.map_err(Error::Submitted)?;
		witnessed.recheck_observation().map_err(Error::Submitted)?;
		Ok(witnessed)
	}
}

fn same_stage_after_link(old: SourceObservation, current: SourceObservation) -> bool {
	old.link_count() == 1
		&& current.link_count() == 2
		&& current.identity() == old.identity()
		&& current.len() == old.len()
		&& current.mode() == old.mode()
		&& current.owner() == old.owner()
		&& current.group() == old.group()
		&& current.modified_at() == old.modified_at()
}

fn observe_two_names(
	stage: &RetainedSuffixReadback<'_, '_>,
	name: &[u8; 40],
) -> Result<(SourceObservation, [File; 2]), StageError> {
	let reader = stage.reader;
	let job = reader.lease.job();
	let mount = job.root.mount;
	let directory = reader
		.inventory
		.directory
		.as_ref()
		.ok_or(StageError::IdentityChanged)?;
	job.recheck()?;
	directory.recheck(
		&job.directory.file,
		OsStr::new(crate::linux::job::STAGE),
		mount,
	)?;
	let held = &stage.file.file;
	let current = SourceObservation::capture(&fs::fstat(held)?).map_err(StageError::ReadBack)?;
	if mount_id(held)? != mount || current.link_count() != 2 {
		return Err(StageError::IdentityChanged);
	}
	let names = [
		open_path(
			&directory.file,
			crate::linux::stage::component(reader.selection.stage),
		)?
		.ok_or(StageError::IdentityChanged)?,
		open_path(&job.directory.file, OsStr::from_bytes(name))?
			.ok_or(StageError::IdentityChanged)?,
	];
	check_aliases(&names, current, mount)?;
	check_absent(
		&job.root.directory,
		crate::linux::stage::component(reader.selection.target),
	)?;
	check_no_visible_attributes(held)?;
	crate::linux::source::check_logical_eof(held, current.len()).map_err(StageError::ReadBack)?;
	let after = SourceObservation::capture(&fs::fstat(held)?).map_err(StageError::ReadBack)?;
	current.recheck(after).map_err(StageError::ReadBack)?;
	directory.recheck(
		&job.directory.file,
		OsStr::new(crate::linux::job::STAGE),
		mount,
	)?;
	job.recheck()?;
	check_aliases(&names, current, mount)?;
	Ok((current, names))
}

fn check_aliases(
	names: &[File; 2],
	stamp: SourceObservation,
	mount: u64,
) -> Result<(), StageError> {
	for named in names {
		if mount_id(named)? != mount {
			return Err(StageError::IdentityChanged);
		}
		let stat = SourceObservation::capture(&fs::fstat(named)?).map_err(StageError::ReadBack)?;
		stamp.recheck(stat).map_err(StageError::ReadBack)?;
	}
	Ok(())
}

impl WitnessedSuffixReadback<'_, '_> {
	pub(in crate::linux::recovery::writer) fn observe_barriered_metadata(
		&self,
	) -> Result<SourceObservation, StageError> {
		self.recheck_observation()?;
		if self.stamp.mode() != crate::linux::stage::FILE_MODE.as_raw_mode()
			|| self.stamp.owner() != rustix::process::geteuid().as_raw()
			|| self.stamp.group() != rustix::process::getegid().as_raw()
		{
			return Err(StageError::UnsafeFile);
		}
		Ok(self.stamp)
	}
}

impl ReadView for WitnessedSuffixReadback<'_, '_> {
	type Error = StageError;

	fn length(&self) -> u64 {
		self.stamp.len()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.stage.lane.recheck()?;
		let mount = self.stage.stage.reader.lease.job().root.mount;
		let (current, _fresh_aliases) = observe_two_names(&self.stage.stage, &self.name)?;
		check_aliases(&self.aliases, self.stamp, mount)?;
		self.stamp.recheck(current).map_err(StageError::ReadBack)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.stage.read_exact_at(offset, bytes)
	}
}
