use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;

use exacopy_endpoint::linux_job::JobFileIdentity;

use super::super::{
	FilePolicy, PrivateDirectory, RecoveryFile, RetainedPrefixSelection, STAGE, StageError,
	check_absent, component, open_regular, recheck_regular,
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

impl<'lease> WitnessedTerminalJournal<'lease> {
	/// Pins the original public file and witness for independent read-only assessment.
	/// # Errors
	/// Refuses a changed or unsafe namespace, original journal or held file.
	pub fn inspect_published<'name>(
		&self,
		selection: WitnessedPublishedSelection<'name>,
	) -> Result<WitnessedPublishedArtifacts<'_, 'lease, 'name>, StageError> {
		self.recheck()?;
		let job = self.lease.job();
		if selection.job != job.identity().into()
			|| selection.destination != job.destination_identity().into()
			|| selection.journal_end != self.segment_length()
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
		let held = WitnessedPublishedArtifacts {
			records: self,
			selection,
			stage,
			target,
			witness,
		};
		held.recheck()?;
		Ok(held)
	}
}

/// Simultaneously held exact public and witness names under the original read lease.
#[must_use]
pub struct WitnessedPublishedArtifacts<'held, 'lease, 'name> {
	pub(super) records: &'held WitnessedTerminalJournal<'lease>,
	selection: WitnessedPublishedSelection<'name>,
	stage: PrivateDirectory,
	target: RecoveryFile,
	witness: RecoveryFile,
}

impl WitnessedPublishedArtifacts<'_, '_, '_> {
	/// Actual held public alias of the selected original file.
	#[must_use]
	pub const fn target(&self) -> &RecoveryFile {
		&self.target
	}

	/// Rechecks aliases, exact metadata/EOF and original journal after reading.
	/// # Errors
	/// Refuses changed or unreadable physical evidence.
	pub fn recheck(&self) -> Result<(), StageError> {
		self.records.recheck()?;
		self.check_names()?;
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
			.map_err(StageError::ReadBack)?;
		self.check_names()?;
		self.records.recheck()
	}

	fn check_names(&self) -> Result<(), StageError> {
		let job = self.records.lease.job();
		let mount = job.root.mount;
		let parent = &job.directory.file;
		self.stage.recheck(parent, OsStr::new(STAGE), mount)?;
		check_absent(&self.stage.file, component(self.selection.stage.stage))?;
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
		self.stage.recheck(parent, OsStr::new(STAGE), mount)
	}
}
