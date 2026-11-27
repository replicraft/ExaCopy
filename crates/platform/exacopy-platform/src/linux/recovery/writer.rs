use std::ffi::OsStr;
use std::fs::File;
use std::io::{Seek as _, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, FlockOperation, OFlags};
use rustix::io::Errno;

use super::super::journal_segment::LinuxJournalSegment;
use super::super::source::reopen_regular_for_append;
use super::super::stage::{
	component, create_private_directory, create_private_file, sync_directory,
};
use super::lease::{lock_job, reopen_directory};
use super::{
	DestinationRoot, FIRST_SEGMENT, FileIdentity, FilePolicy, JOURNAL, PrivateDirectory, RECEIPT,
	RECEIPTS, RecoveryFile, RecoveryInventory, RecoveryJob, RecoveryStageAnchor, SourceObservation,
	StageError, mount_id, open_checked_record, open_path, recheck_regular,
};

mod fresh;
mod prefix;
mod resume;
mod retained;
mod witness_reservation;

pub use fresh::FreshRecoveryStage;
pub use prefix::{
	ProtectedWitnessEffect, ProtectedWitnessError, RetainedPrefixRead, RetainedPrefixSelection,
	RetainedSuffixReadback, RetainedSuffixWriter, SuffixEffect, SuffixError, SyncedRetainedPrefix,
	SyncedSuffixRange, WitnessCredentialLane, WitnessLinkCandidate, WitnessedSuffixReadback,
};
pub use resume::RecoveryStageDirectory;
pub use retained::RetainedStage;
pub use witness_reservation::{
	ActiveWitnessReservation, ContinuationReservationError, PendingProtectedWitness,
	PendingWitnessReservation, ReservedContinuationRequest, ReservedJournalRead,
	SealedProtectedWitness, WitnessPrepublicationAppend, WitnessPrepublicationPhase,
	WitnessPublication, WitnessPublicationError, WitnessPublicationName, WitnessPublicationNames,
	WitnessPublicationObservation, WitnessPublicationRequest, WitnessReservationAuthority,
	WitnessReservationEffect, WitnessReservationError, WitnessReservationGateRequest,
	WitnessReservationObservationError, WitnessReservationPlan,
};

#[cfg(test)]
mod tests;

impl DestinationRoot {
	/// Acquires a nonblocking exclusive reconciliation lease on the expected held job.
	///
	/// The expected identity should come from a live job handle. The lease
	/// coordinates with writers and inspectors using the same in-kernel job lock.
	///
	/// # Errors
	/// Rejects a busy, unsafe, missing, or rebound job and lock errors.
	pub fn try_recovery_write_lease(
		&self,
		name: UnixComponent<'_>,
		expected_job: FileIdentity,
	) -> Result<RecoveryWriteLease<'_>, StageError> {
		let job = self.open_recovery_job(name)?;
		if job.identity() != expected_job {
			return Err(StageError::IdentityChanged);
		}
		let lock = lock_job(&job, FlockOperation::NonBlockingLockExclusive)?;
		Ok(RecoveryWriteLease {
			job,
			lock,
			stage_access: Mutex::new(()),
			suffix_barrier_started: AtomicBool::new(false),
			journal_access: Mutex::new(()),
			journal_reservation_started: AtomicBool::new(false),
		})
	}
}

/// Exclusive cooperative access to one held private job and its recovery effects.
///
/// The caller establishes current record authority and publication evidence
/// before using mutation methods. Hold this lease until record writers close
/// and all requested barriers and observations finish.
#[derive(Debug)]
#[must_use]
pub struct RecoveryWriteLease<'root> {
	job: RecoveryJob<'root>,
	lock: File,
	stage_access: Mutex<()>,
	suffix_barrier_started: AtomicBool,
	journal_access: Mutex<()>,
	journal_reservation_started: AtomicBool,
}

impl RecoveryWriteLease<'_> {
	fn try_stage_access(&self) -> Result<MutexGuard<'_, ()>, StageError> {
		let access = self
			.stage_access
			.try_lock()
			.map_err(|_| StageError::JobBusy)?;
		if self.suffix_barrier_started.load(Ordering::Relaxed) {
			return Err(StageError::JobBusy);
		}
		Ok(access)
	}

	/// Returns the held inspection capability protected by the exclusive lease.
	#[must_use]
	pub fn job(&self) -> &RecoveryJob<'_> {
		&self.job
	}

	/// Requires two names to be observed absent under this held job root.
	///
	/// Each lookup is relative to the held directory and does not follow links.
	/// These observations grant no authority for later effects and carry no
	/// durability claim.
	///
	/// # Errors
	/// Refuses an occupied name, a changed job or root binding, or a lookup failure.
	pub fn require_job_root_names_absent(
		&self,
		names: [UnixComponent<'_>; 2],
	) -> Result<(), StageError> {
		self.job.recheck()?;
		for name in names {
			super::check_absent(&self.job.directory.file, component(name))?;
		}
		self.job.recheck()
	}

	/// Retains read-only pins for a private stage after its writer scope ends.
	///
	/// # Errors
	/// Refuses a foreign inventory, active stage capability, missing stage,
	/// occupied target, changed namespace or descriptor failure.
	pub fn pin_stopped_stage(
		&self,
		inventory: RecoveryInventory<'_>,
	) -> Result<RecoveryStageAnchor, StageError> {
		if !std::ptr::eq(inventory.job, self.job()) {
			return Err(StageError::IdentityChanged);
		}
		let _access = self.try_stage_access()?;
		inventory.into_stage_anchor()
	}

	/// Opens the exact inspected first segment for appending at its captured end.
	///
	/// The returned segment keeps this lease borrowed and prevents a second
	/// journal writer through it. The caller verifies a complete, supported
	/// chain and handles uncertain writes. Opening neither creates nor truncates
	/// the segment.
	///
	/// # Examples
	/// A segment cannot escape the lease that opened it.
	/// ```compile_fail,E0515
	/// use exacopy_platform::linux::{LinuxJournalSegment, RecoveryFile, RecoveryWriteLease, StageError};
	/// fn detach<'root>(lease: RecoveryWriteLease<'root>, expected: &RecoveryFile)
	///     -> Result<LinuxJournalSegment<'root>, StageError> {
	///     lease.open_first_segment_for_append(expected)
	/// }
	/// ```
	///
	/// # Errors
	/// Rejects missing, unsafe, rebound, or changed segments, an already open
	/// writer in this lease, and reopen failures.
	pub fn open_first_segment_for_append(
		&self,
		expected: &RecoveryFile,
	) -> Result<LinuxJournalSegment<'_>, StageError> {
		let held = self.hold_first_segment_for_append(expected)?;
		Ok(LinuxJournalSegment::recovered(held.file, held.writer))
	}

	fn hold_first_segment_for_append(
		&self,
		expected: &RecoveryFile,
	) -> Result<HeldFirstSegment<'_>, StageError> {
		let writer = self
			.journal_access
			.try_lock()
			.map_err(|_| StageError::JobBusy)?;
		if self.journal_reservation_started.load(Ordering::Relaxed) {
			return Err(StageError::JobBusy);
		}
		let job = &self.job;
		let mount = job.root.mount;
		let parent = &job.directory.file;
		let journal_name = OsStr::new(JOURNAL);
		let name = OsStr::new(FIRST_SEGMENT);
		job.recheck()?;
		let journal = PrivateDirectory::open(parent, journal_name, mount)?.ok_or(Errno::NOENT)?;
		recheck_regular(
			&journal.file,
			name,
			mount,
			FilePolicy::Record,
			Some(expected),
		)?;
		expected
			.recheck_observation()
			.map_err(StageError::ReadBack)?;
		let (mut file, stat) =
			reopen_regular_for_append(&expected.file).map_err(StageError::ReadBack)?;
		FilePolicy::Record.check(&stat)?;
		if mount_id(&file)? != mount {
			return Err(StageError::IdentityChanged);
		}
		let current = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
		expected
			.observation
			.recheck(current)
			.map_err(StageError::ReadBack)?;
		let end = file.seek(SeekFrom::End(0)).map_err(StageError::System)?;
		if end != expected.len() {
			return Err(StageError::IdentityChanged);
		}
		recheck_regular(
			&journal.file,
			name,
			mount,
			FilePolicy::Record,
			Some(expected),
		)?;
		journal.recheck(parent, journal_name, mount)?;
		job.recheck()?;
		Ok(HeldFirstSegment {
			file,
			writer,
			journal,
		})
	}

	/// Requests file and directory barriers for an observed, already-published name.
	///
	/// The held inventory must describe this lease's job, a present public target
	/// and private stage directory, and an absent former stage name. The caller
	/// verifies that the target and stage directory match the authoritative records.
	///
	/// # Errors
	/// Refuses a mismatched job or inventory and reports failed observations and barriers.
	pub fn sync_publication(&self, inventory: &RecoveryInventory<'_>) -> Result<(), StageError> {
		if !std::ptr::eq(inventory.job, &self.job) || inventory.stage.is_some() {
			return Err(StageError::IdentityChanged);
		}
		let target = inventory
			.target
			.as_ref()
			.ok_or(StageError::IdentityChanged)?;
		let stage = inventory
			.directory
			.as_ref()
			.ok_or(StageError::IdentityChanged)?;
		inventory.recheck()?;
		let directory = reopen_directory(&stage.file, stage.identity, self.job.root.mount)?;
		inventory.recheck()?;
		sync_file(&target.file)?;
		sync_directory(&directory)?;
		self.job.root.sync_directory()?;
		inventory.recheck()
	}

	/// Requests a barrier on the leased and currently bound job directory.
	///
	/// # Errors
	/// Reports changed bindings or a failed barrier.
	pub fn sync_job_directory(&self) -> Result<(), StageError> {
		self.job.recheck()?;
		sync_directory(&self.lock)?;
		self.job.recheck()
	}

	/// Exclusively creates the fixed receipt directory under the held write lease.
	/// # Errors
	/// Refuses an existing name or changed native bindings. A newly created
	/// directory can remain after a later refusal for explicit reconciliation.
	pub fn create_receipt_directory(&self) -> Result<RecoveryReceiptDirectory<'_>, StageError> {
		self.job.recheck()?;
		let mount = self.job.root.mount;
		let name = OsStr::new(RECEIPTS);
		let (file, identity) = create_private_directory(&self.job.directory.file, name, mount)?;
		let receipts = RecoveryReceiptDirectory {
			job: &self.job,
			directory: PrivateDirectory { file, identity },
		};
		receipts.recheck()?;
		Ok(receipts)
	}

	/// Opens the fixed private receipt directory or exclusively creates it if absent.
	///
	/// # Errors
	/// Rejects unsafe, rebound, or concurrently created entries or failed syscalls.
	/// A new directory can remain after a later error.
	pub fn open_receipt_directory(&self) -> Result<RecoveryReceiptDirectory<'_>, StageError> {
		self.job.recheck()?;
		let parent = &self.job.directory.file;
		let mount = self.job.root.mount;
		let name = OsStr::new(RECEIPTS);
		let directory = match PrivateDirectory::open(parent, name, mount)? {
			Some(directory) => directory,
			None => {
				let (file, identity) = create_private_directory(parent, name, mount)?;
				PrivateDirectory { file, identity }
			}
		};
		let receipts = RecoveryReceiptDirectory {
			job: &self.job,
			directory,
		};
		receipts.recheck()?;
		Ok(receipts)
	}
}

struct HeldFirstSegment<'lease> {
	file: File,
	writer: MutexGuard<'lease, ()>,
	journal: PrivateDirectory,
}

/// Access to the fixed receipt of a job protected by an exclusive recovery lease.
pub struct RecoveryReceiptDirectory<'lease> {
	job: &'lease RecoveryJob<'lease>,
	directory: PrivateDirectory,
}

impl RecoveryReceiptDirectory<'_> {
	/// Opens the current private receipt read-only, or observes its absence.
	///
	/// # Errors
	/// Rejects unsafe, rebound, or unreadable entries.
	pub fn open_receipt(&self) -> Result<Option<RecoveryFile>, StageError> {
		self.recheck()?;
		let file = open_checked_record(
			&self.directory.file,
			OsStr::new(RECEIPT),
			self.job.root.mount,
		)?;
		self.recheck()?;
		Ok(file)
	}

	/// Exclusively creates the fixed private receipt record without replacing an incumbent.
	///
	/// The caller writes the authoritative receipt and closes the new writer before
	/// releasing the lease. An existing receipt is only accessible read-only.
	///
	/// # Errors
	/// Rejects unsafe or rebound directories, collisions, and failed syscalls.
	/// A newly created record can remain after a later error.
	pub fn create_receipt(&self) -> Result<File, StageError> {
		self.recheck()?;
		let name = OsStr::new(RECEIPT);
		let mount = self.job.root.mount;
		let (file, created) = create_private_file(&self.directory.file, mount, name, OFlags::RDWR)?;
		let named = open_path(&self.directory.file, name)?.ok_or(StageError::IdentityChanged)?;
		let stat = fs::fstat(&named)?;
		FilePolicy::Record.check(&stat)?;
		if FileIdentity::from_stat(&stat) != FileIdentity::from_stat(&created)
			|| mount_id(&named)? != mount
		{
			return Err(StageError::IdentityChanged);
		}
		self.recheck()?;
		Ok(file)
	}

	/// Requests a barrier on the exact inspected receipt inode.
	///
	/// # Errors
	/// Reports mismatched receipt observations or a failed barrier.
	pub fn sync_receipt(&self, receipt: &RecoveryFile) -> Result<(), StageError> {
		self.recheck_receipt(receipt)?;
		sync_file(&receipt.file)?;
		self.recheck_receipt(receipt)
	}

	/// Requests a barrier on the currently bound receipt directory.
	///
	/// # Errors
	/// Reports changed bindings or a failed barrier.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.recheck()?;
		let directory = reopen_directory(
			&self.directory.file,
			self.directory.identity,
			self.job.root.mount,
		)?;
		self.recheck()?;
		sync_directory(&directory)?;
		self.recheck()
	}

	fn recheck_receipt(&self, receipt: &RecoveryFile) -> Result<(), StageError> {
		self.recheck()?;
		recheck_regular(
			&self.directory.file,
			OsStr::new(RECEIPT),
			self.job.root.mount,
			FilePolicy::Record,
			Some(receipt),
		)?;
		receipt
			.recheck_observation()
			.map_err(StageError::ReadBack)?;
		self.recheck()
	}

	fn recheck(&self) -> Result<(), StageError> {
		self.job.recheck()?;
		self.directory.recheck(
			&self.job.directory.file,
			OsStr::new(RECEIPTS),
			self.job.root.mount,
		)
	}
}

impl std::fmt::Debug for RecoveryReceiptDirectory<'_> {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("RecoveryReceiptDirectory")
			.field("identity", &self.directory.identity)
			.finish_non_exhaustive()
	}
}

fn sync_file(file: &File) -> Result<(), StageError> {
	file.sync_all().map_err(StageError::BarrierFailed)
}
