use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt as _;

use exacopy_endpoint::linux_job::JobFileIdentity;

use super::witnessed_names::matches_names;
use super::{
	FIRST_SEGMENT, FilePolicy, JOURNAL, PrivateDirectory, RecoveryFile, RecoveryReadLease,
	RetainedPrefixSelection, StageError, WitnessReceiptNames, check_absent, open_checked_record,
	recheck_regular,
};
use crate::linux::job::OWNER;
use crate::linux::stage::check_no_visible_attributes;

mod published;
pub use published::{
	WitnessedPublicPins, WitnessedPublicSelection, WitnessedPublishedArtifacts,
	WitnessedPublishedSelection,
};

const MAX_FIRST_SEGMENT: u64 = 64 * 1024 * 1024;
const MAX_RECEIPT_LENGTH: u16 = 6_144;

/// The sole selected receipt name observed in the held job directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedReceiptLocation {
	/// The exact pending name exists and the final name is absent.
	Pending,
	/// The exact final name exists and the pending name is absent.
	Final,
}

/// Native facts selected from independently authenticated receipt history.
#[derive(Clone, Copy)]
pub struct WitnessedTerminalSelection<'name> {
	/// Protected job root selected by the history.
	pub job: JobFileIdentity,
	/// Exact public target parent.
	pub destination: JobFileIdentity,
	/// Original private directory and inode, with actual stage and target names.
	pub stage: RetainedPrefixSelection<'name>,
	/// Exact witness name in the protected job root.
	pub witness_name: [u8; 40],
	/// Exact receipt pending name.
	pub pending_name: [u8; 101],
	/// Exact receipt final name.
	pub final_name: [u8; 99],
	/// File owner selected by the recorded metadata policy.
	pub uid: u32,
	/// File group selected by the recorded metadata policy.
	pub gid: u32,
	/// Exact selected public data extent.
	pub extent: u64,
	/// Exact recorded receipt inode.
	pub receipt: JobFileIdentity,
	/// Exact canonical receipt byte count.
	pub receipt_len: u16,
	/// Exact end offset of the accepted journal.
	pub journal_end: u64,
}

/// Original held owner and first segment under a single shared recovery lease.
#[must_use]
pub struct WitnessedTerminalJournal<'lease> {
	lease: &'lease RecoveryReadLease<'lease>,
	owner: RecoveryFile,
	directory: PrivateDirectory,
	segment: RecoveryFile,
}

impl RecoveryReadLease<'_> {
	/// Pins the owner, journal directory and bounded first segment on this lease.
	///
	/// The caller authenticates the complete bytes independently. This holder
	/// makes no inference about semantic phase or permission.
	///
	/// # Errors
	/// Refuses missing, unsafe, changed or out-of-bound records.
	pub fn hold_witnessed_terminal_journal(
		&self,
	) -> Result<WitnessedTerminalJournal<'_>, StageError> {
		self.recheck()?;
		let job = self.job();
		let mount = job.root.mount;
		let parent = &job.directory.file;
		let owner = open_checked_record(parent, OsStr::new(OWNER), mount)?
			.ok_or(StageError::IdentityChanged)?;
		let directory = PrivateDirectory::open(parent, OsStr::new(JOURNAL), mount)?
			.ok_or(StageError::IdentityChanged)?;
		let segment = open_checked_record(&directory.file, OsStr::new(FIRST_SEGMENT), mount)?
			.ok_or(StageError::IdentityChanged)?;
		if owner.is_empty() || segment.is_empty() || segment.len() > MAX_FIRST_SEGMENT {
			return Err(StageError::IdentityChanged);
		}
		let records = WitnessedTerminalJournal {
			lease: self,
			owner,
			directory,
			segment,
		};
		records.recheck()?;
		Ok(records)
	}
}

impl<'lease> WitnessedTerminalJournal<'lease> {
	/// Returns the original held owner record for bounded independent authentication.
	#[must_use]
	pub const fn owner(&self) -> &RecoveryFile {
		&self.owner
	}

	/// Returns a new byte-zero reader bounded by the held segment's observed length.
	#[must_use]
	pub const fn journal(&self) -> WitnessedTerminalSegment<'_> {
		WitnessedTerminalSegment {
			file: &self.segment,
			offset: 0,
		}
	}

	/// Exact length originally observed on this held first segment.
	#[must_use]
	pub fn segment_length(&self) -> u64 {
		self.segment.len()
	}

	/// Checks the same original lease, owner and journal records, names and EOF.
	///
	/// # Errors
	/// Refuses an unsafe or changed binding, file, length or enclosing directory.
	pub fn recheck(&self) -> Result<(), StageError> {
		self.lease.recheck()?;
		let job = self.lease.job();
		let mount = job.root.mount;
		let parent = &job.directory.file;
		self.directory.recheck(parent, OsStr::new(JOURNAL), mount)?;
		recheck_regular(
			parent,
			OsStr::new(OWNER),
			mount,
			FilePolicy::Record,
			Some(&self.owner),
		)?;
		recheck_regular(
			&self.directory.file,
			OsStr::new(FIRST_SEGMENT),
			mount,
			FilePolicy::Record,
			Some(&self.segment),
		)?;
		for record in [&self.owner, &self.segment] {
			record.check_logical_eof().map_err(StageError::ReadBack)?;
			record.recheck_observation().map_err(StageError::ReadBack)?;
		}
		self.directory.recheck(parent, OsStr::new(JOURNAL), mount)?;
		self.lease.recheck()
	}

	/// Pins the native namespace selected by the authenticated terminal records.
	///
	/// The caller independently authenticates the original owner and complete
	/// journal on this holder. The caller must compare the target digest and
	/// exact canonical receipt bytes, check current profile facts, and recheck
	/// this view around those reads. The result conveys no current authority.
	///
	/// # Errors
	/// Refuses changed, absent, occupied, aliased or unsafe native objects.
	pub fn inspect<'name>(
		&self,
		selection: WitnessedTerminalSelection<'name>,
	) -> Result<WitnessedTerminalArtifacts<'_, 'lease, 'name>, StageError> {
		self.inspect_receipt(selection, Some(WitnessedReceiptLocation::Final))
	}

	/// Pins the witnessed public file and exactly one of the protected receipt names.
	///
	/// The caller independently authenticates the owner and complete journal,
	/// compares the public digest and canonical receipt bytes, confirms the
	/// current profile, and rechecks the returned view around the reads.
	///
	/// # Errors
	/// Refuses missing, simultaneous, unsafe or changed receipt names or other evidence.
	pub fn inspect_receipt_ready<'name>(
		&self,
		selection: WitnessedTerminalSelection<'name>,
	) -> Result<WitnessedTerminalArtifacts<'_, 'lease, 'name>, StageError> {
		self.inspect_receipt(selection, None)
	}

	fn inspect_receipt<'name>(
		&self,
		selection: WitnessedTerminalSelection<'name>,
		expected: Option<WitnessedReceiptLocation>,
	) -> Result<WitnessedTerminalArtifacts<'_, 'lease, 'name>, StageError> {
		self.recheck()?;
		let job = self.lease.job();
		if !matches_names(
			&WitnessReceiptNames {
				pending: selection.pending_name,
				final_name: selection.final_name,
			},
			&selection.witness_name,
		) || selection.job != job.identity().into()
			|| selection.destination != job.destination_identity().into()
			|| selection.journal_end != self.segment_length()
			|| selection.receipt_len == 0
			|| selection.receipt_len > MAX_RECEIPT_LENGTH
			|| [
				selection.job,
				selection.destination,
				selection.stage.directory,
				selection.stage.file,
				self.owner.identity().into(),
				self.segment.identity().into(),
				self.directory.identity.into(),
			]
			.contains(&selection.receipt)
		{
			return Err(StageError::IdentityChanged);
		}

		let mount = job.root.mount;
		let parent = &job.directory.file;
		let pending_name = OsStr::from_bytes(&selection.pending_name);
		if expected == Some(WitnessedReceiptLocation::Final) {
			check_absent(parent, pending_name)?;
		}
		let published = self.inspect_published(WitnessedPublishedSelection {
			job: selection.job,
			destination: selection.destination,
			stage: selection.stage,
			witness_name: selection.witness_name,
			uid: selection.uid,
			gid: selection.gid,
			extent: selection.extent,
			journal_end: selection.journal_end,
		})?;
		let pending = if expected == Some(WitnessedReceiptLocation::Final) {
			None
		} else {
			open_checked_record(parent, pending_name, mount)?
		};
		let final_receipt =
			open_checked_record(parent, OsStr::from_bytes(&selection.final_name), mount)?;
		let (location, receipt) = match (pending, final_receipt) {
			(Some(receipt), None) => (WitnessedReceiptLocation::Pending, receipt),
			(None, Some(receipt)) => (WitnessedReceiptLocation::Final, receipt),
			_ => return Err(StageError::IdentityChanged),
		};
		let artifacts = WitnessedTerminalArtifacts {
			published,
			selection,
			location,
			receipt,
		};
		artifacts.recheck()?;
		Ok(artifacts)
	}
}

/// Checked positioned reader over an exact captured segment extent.
pub struct WitnessedTerminalSegment<'held> {
	file: &'held RecoveryFile,
	offset: u64,
}

impl Read for WitnessedTerminalSegment<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		let remaining = self.file.len().checked_sub(self.offset).ok_or_else(|| {
			io::Error::other("terminal journal reader passed its captured extent")
		})?;
		let length = usize::try_from(remaining)
			.unwrap_or(usize::MAX)
			.min(buffer.len());
		if length == 0 {
			if remaining == 0 {
				self.file.check_logical_eof().map_err(io::Error::other)?;
			}
			return Ok(0);
		}
		self.file
			.read_exact_at(self.offset, &mut buffer[..length])
			.map_err(io::Error::other)?;
		let read = u64::try_from(length).map_err(io::Error::other)?;
		self.offset = self
			.offset
			.checked_add(read)
			.ok_or_else(|| io::Error::other("terminal journal reader offset overflow"))?;
		Ok(length)
	}
}

/// Held, read-only terminal artifacts and exact namespace absences on the shared lease.
#[must_use]
pub struct WitnessedTerminalArtifacts<'held, 'lease, 'name> {
	published: WitnessedPublishedArtifacts<'held, 'lease, 'name>,
	selection: WitnessedTerminalSelection<'name>,
	location: WitnessedReceiptLocation,
	receipt: RecoveryFile,
}

impl WitnessedTerminalArtifacts<'_, '_, '_> {
	/// Actual held public target of the exact original stage inode.
	#[must_use]
	pub const fn target(&self) -> &RecoveryFile {
		self.published.target()
	}

	/// Location of the receipt under the held read lease.
	#[must_use]
	pub const fn receipt_location(&self) -> WitnessedReceiptLocation {
		self.location
	}

	/// Actual held receipt inode, with the other receipt name independently absent.
	#[must_use]
	pub const fn receipt(&self) -> &RecoveryFile {
		&self.receipt
	}

	/// Checks the original protected namespace, exact two-link data and one-link receipt.
	///
	/// # Errors
	/// Refuses any unsafe alias, rebind, metadata or extent change or missing evidence.
	pub fn recheck(&self) -> Result<(), StageError> {
		self.published.recheck()?;
		self.check_receipt_names()?;
		let selected = self.selection;
		let receipt = self.receipt.observation();
		if JobFileIdentity::from(receipt.identity()) != selected.receipt
			|| receipt.owner() != selected.uid
			|| receipt.group() != selected.gid
			|| receipt.len() != u64::from(selected.receipt_len)
		{
			return Err(StageError::IdentityChanged);
		}
		check_no_visible_attributes(&self.receipt.file)?;
		self.receipt
			.check_logical_eof()
			.map_err(StageError::ReadBack)?;
		self.receipt
			.recheck_observation()
			.map_err(StageError::ReadBack)?;
		self.published.recheck()?;
		self.check_receipt_names()?;
		self.published.recheck()
	}

	fn check_receipt_names(&self) -> Result<(), StageError> {
		let job = self.published.records.lease.job();
		let parent = &job.directory.file;
		let pending = OsStr::from_bytes(&self.selection.pending_name);
		let final_name = OsStr::from_bytes(&self.selection.final_name);
		let (name, absent) = match self.location {
			WitnessedReceiptLocation::Pending => (pending, final_name),
			WitnessedReceiptLocation::Final => (final_name, pending),
		};
		check_absent(parent, absent)?;
		recheck_regular(
			parent,
			name,
			job.root.mount,
			FilePolicy::Record,
			Some(&self.receipt),
		)?;
		check_absent(parent, absent)
	}
}

#[cfg(test)]
mod tests;
