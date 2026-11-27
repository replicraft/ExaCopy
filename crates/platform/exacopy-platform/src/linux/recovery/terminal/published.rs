use std::ffi::OsStr;
use std::fmt;
use std::os::unix::ffi::OsStrExt as _;

use exacopy_endpoint::linux_job::JobFileIdentity;

use super::super::{
	FilePolicy, PrivateDirectory, RecoveryFile, RecoveryJob, RecoveryWriteLease,
	RetainedPrefixSelection, STAGE, StageError, check_absent, component, open_regular,
	recheck_regular,
};
use super::WitnessedTerminalJournal;
use crate::linux::stage::check_no_visible_attributes;

/// Exact historical namespace and metadata selected for a witnessed public read.
#[derive(Clone, Copy)]
pub struct WitnessedPublishedSelection<'name> {
	/// Protected job root selected by the history.
	pub job: JobFileIdentity,
	/// Exact public target parent.
	pub destination: JobFileIdentity,
	/// Original private stage and selected target names and stage identities.
	pub stage: RetainedPrefixSelection<'name>,
	/// Exact protected witness basename.
	pub witness_name: [u8; 40],
	/// Exact selected owner.
	pub uid: u32,
	/// Exact selected group.
	pub gid: u32,
	/// Exact public file extent.
	pub extent: u64,
	/// Exact authenticated journal end.
	pub journal_end: u64,
}

/// Exact namespace and metadata selected for the public aliases under exclusive recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessedPublicSelection<'name> {
	/// Protected job root selected by the history.
	pub job: JobFileIdentity,
	/// Exact public target parent.
	pub destination: JobFileIdentity,
	/// Original private stage and selected target names and stage identities.
	pub stage: RetainedPrefixSelection<'name>,
	/// Exact protected witness basename.
	pub witness_name: [u8; 40],
	/// Exact selected owner.
	pub uid: u32,
	/// Exact selected group.
	pub gid: u32,
	/// Exact public file extent.
	pub extent: u64,
}

impl<'name> From<WitnessedPublishedSelection<'name>> for WitnessedPublicSelection<'name> {
	fn from(selection: WitnessedPublishedSelection<'name>) -> Self {
		Self {
			job: selection.job,
			destination: selection.destination,
			stage: selection.stage,
			witness_name: selection.witness_name,
			uid: selection.uid,
			gid: selection.gid,
			extent: selection.extent,
		}
	}
}

impl<'lease> WitnessedTerminalJournal<'lease> {
	/// Pins the original public file and witness for independent read-only assessment.
	/// # Errors
	/// Refuses a changed or unsafe namespace, original journal or held file.
	pub fn inspect_published<'name>(
		&self,
		selection: WitnessedPublishedSelection<'name>,
	) -> Result<WitnessedPublishedArtifacts<'_, 'lease, 'name>, StageError> {
		self.recheck()?;
		if selection.journal_end != self.segment_length() {
			return Err(StageError::IdentityChanged);
		}
		let names = PublishedNames::open(self.lease.job(), selection.into())?;
		let held = WitnessedPublishedArtifacts {
			records: self,
			names,
		};
		held.recheck()?;
		Ok(held)
	}
}

/// Simultaneously held exact public and witness names under the original read lease.
#[must_use]
pub struct WitnessedPublishedArtifacts<'held, 'lease, 'name> {
	pub(super) records: &'held WitnessedTerminalJournal<'lease>,
	names: PublishedNames<'name>,
}

impl WitnessedPublishedArtifacts<'_, '_, '_> {
	/// Actual held public alias of the selected original file.
	#[must_use]
	pub const fn target(&self) -> &RecoveryFile {
		&self.names.target
	}

	/// Rechecks aliases, exact metadata/EOF and original journal after reading.
	/// # Errors
	/// Refuses changed or unreadable physical evidence.
	pub fn recheck(&self) -> Result<(), StageError> {
		let job = self.records.lease.job();
		self.records.recheck()?;
		self.names.check_names(job)?;
		self.names.check_files()?;
		self.records.recheck()?;
		self.names.check_names(job)?;
		self.records.recheck()
	}
}

impl RecoveryWriteLease<'_> {
	/// Pins the selected public and protected witness aliases on this exclusive lease.
	///
	/// The caller authenticates the historical selection and verifies the public
	/// bytes. This holder has read-only handles and can remain live across a journal
	/// append on the same lease.
	///
	/// # Examples
	/// The pins cannot escape the exclusive lease that opened them.
	/// ```compile_fail,E0515
	/// use exacopy_platform::linux::{
	///     RecoveryWriteLease, StageError, WitnessedPublicPins, WitnessedPublicSelection,
	/// };
	/// fn detach<'root>(
	///     lease: RecoveryWriteLease<'root>,
	///     selection: WitnessedPublicSelection<'static>,
	/// ) -> Result<WitnessedPublicPins<'root, 'static>, StageError> {
	///     lease.hold_witnessed_public(selection)
	/// }
	/// ```
	///
	/// # Errors
	/// Refuses a changed or unsafe root, job, stage directory, namespace or file.
	pub fn hold_witnessed_public<'name>(
		&self,
		selection: WitnessedPublicSelection<'name>,
	) -> Result<WitnessedPublicPins<'_, 'name>, StageError> {
		let job = self.job();
		job.recheck()?;
		let names = PublishedNames::open(job, selection)?;
		let pins = WitnessedPublicPins { lease: self, names };
		pins.recheck()?;
		Ok(pins)
	}
}

/// Read-only pins for the exact witnessed public file on one exclusive recovery lease.
#[must_use]
pub struct WitnessedPublicPins<'lease, 'name> {
	lease: &'lease RecoveryWriteLease<'lease>,
	names: PublishedNames<'name>,
}

impl WitnessedPublicPins<'_, '_> {
	/// Returns the original public alias for independent byte verification.
	#[must_use]
	pub const fn target(&self) -> &RecoveryFile {
		&self.names.target
	}

	/// Checks that these pins borrow this exact exclusive lease.
	#[must_use]
	pub fn matches_lease(&self, lease: &RecoveryWriteLease<'_>) -> bool {
		std::ptr::eq(self.lease, lease)
	}

	/// Rechecks the held job, exact aliases and metadata, logical EOF and stage absence.
	///
	/// # Errors
	/// Refuses changed or unreadable physical evidence.
	pub fn recheck(&self) -> Result<(), StageError> {
		let job = self.lease.job();
		job.recheck()?;
		self.names.check_names(job)?;
		self.names.check_files()?;
		self.names.check_names(job)?;
		job.recheck()
	}
}

impl fmt::Debug for WitnessedPublicPins<'_, '_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("WitnessedPublicPins")
			.field("target", &self.names.target)
			.finish_non_exhaustive()
	}
}

struct PublishedNames<'name> {
	selection: WitnessedPublicSelection<'name>,
	stage: PrivateDirectory,
	target: RecoveryFile,
	witness: RecoveryFile,
}

impl<'name> PublishedNames<'name> {
	fn open(
		job: &RecoveryJob<'_>,
		selection: WitnessedPublicSelection<'name>,
	) -> Result<Self, StageError> {
		if selection.job != job.identity().into()
			|| selection.destination != job.destination_identity().into()
			|| !selection.witness_name.starts_with(b"witness.")
			|| !selection.witness_name[8..]
				.iter()
				.all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
		{
			return Err(StageError::IdentityChanged);
		}
		let mount = job.root.mount;
		let parent = &job.directory.file;
		let stage = PrivateDirectory::open(parent, OsStr::new(STAGE), mount)?
			.ok_or(StageError::IdentityChanged)?;
		if selection.stage.directory != stage.identity.into() {
			return Err(StageError::IdentityChanged);
		}
		check_absent(&stage.file, component(selection.stage.stage))?;
		let target = open_regular(
			&job.root.directory,
			component(selection.stage.target),
			mount,
			FilePolicy::WitnessedPublic,
		)?
		.ok_or(StageError::IdentityChanged)?;
		let witness = open_regular(
			parent,
			OsStr::from_bytes(&selection.witness_name),
			mount,
			FilePolicy::WitnessedPublic,
		)?
		.ok_or(StageError::IdentityChanged)?;
		Ok(Self {
			selection,
			stage,
			target,
			witness,
		})
	}

	fn check_files(&self) -> Result<(), StageError> {
		for file in [&self.target, &self.witness] {
			let stamp = file.observation();
			if JobFileIdentity::from(stamp.identity()) != self.selection.stage.file
				|| stamp.owner() != self.selection.uid
				|| stamp.group() != self.selection.gid
				|| stamp.len() != self.selection.extent
			{
				return Err(StageError::IdentityChanged);
			}
			check_no_visible_attributes(&file.file)?;
			file.check_logical_eof().map_err(StageError::ReadBack)?;
			file.recheck_observation().map_err(StageError::ReadBack)?;
		}
		self.target
			.observation()
			.recheck(self.witness.observation())
			.map_err(StageError::ReadBack)
	}

	fn check_names(&self, job: &RecoveryJob<'_>) -> Result<(), StageError> {
		let mount = job.root.mount;
		let parent = &job.directory.file;
		self.stage.recheck(parent, OsStr::new(STAGE), mount)?;
		let private_name = component(self.selection.stage.stage);
		check_absent(&self.stage.file, private_name)?;
		recheck_regular(
			&job.root.directory,
			component(self.selection.stage.target),
			mount,
			FilePolicy::WitnessedPublic,
			Some(&self.target),
		)?;
		recheck_regular(
			parent,
			OsStr::from_bytes(&self.selection.witness_name),
			mount,
			FilePolicy::WitnessedPublic,
			Some(&self.witness),
		)?;
		check_absent(&self.stage.file, private_name)?;
		self.stage.recheck(parent, OsStr::new(STAGE), mount)
	}
}
