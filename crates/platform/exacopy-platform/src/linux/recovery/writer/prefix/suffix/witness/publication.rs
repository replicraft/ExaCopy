use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;

use rustix::fs;

use super::{StageError, WitnessedSuffixReadback, check_aliases, mount_id, open_path};
use crate::linux::recovery::writer::witness_reservation::{
	WitnessPublicationName, WitnessPublicationNames, WitnessPublicationObservation,
};
use crate::linux::source::{SourceObservation, check_logical_eof};
use crate::linux::stage::{PublicationNames, PublishError, check_no_visible_attributes, component};

pub(in crate::linux::recovery::writer) struct WitnessedRename<'held, 'view, 'lease> {
	original: &'held WitnessedSuffixReadback<'view, 'lease>,
	names: PublicationNames<'held>,
}

impl<'view, 'lease> WitnessedSuffixReadback<'view, 'lease> {
	pub(in crate::linux::recovery::writer) fn prepare_rename(
		&self,
	) -> Result<WitnessedRename<'_, 'view, 'lease>, StageError> {
		self.observe_barriered_metadata()?;
		let reader = self.stage.stage.reader;
		let job = reader.lease.job();
		let directory = reader
			.inventory
			.directory
			.as_ref()
			.ok_or(StageError::IdentityChanged)?;
		Ok(WitnessedRename {
			original: self,
			names: PublicationNames {
				stage: &directory.file,
				stage_name: component(reader.selection.stage),
				destination: job.root,
				target_name: component(reader.selection.target),
			},
		})
	}
}

impl WitnessedRename<'_, '_, '_> {
	pub(in crate::linux::recovery::writer) fn submit<G>(
		self,
		guard: G,
	) -> WitnessPublicationObservation {
		let result = self.names.rename();
		drop(guard);
		let (names, held) = self.inspect();
		match result {
			Ok(()) => match self.confirm(&names, &held, true) {
				Ok(target) => WitnessPublicationObservation::Published(target),
				Err(cause) => WitnessPublicationObservation::Reconcile {
					submission: Ok(()),
					names: Box::new(names),
					observation_failure: Some(cause),
				},
			},
			Err(PublishError::Conflict) => match self.confirm(&names, &held, false) {
				Ok(target) => WitnessPublicationObservation::Conflict(target),
				Err(cause) => WitnessPublicationObservation::Reconcile {
					submission: Err(PublishError::Conflict),
					names: Box::new(names),
					observation_failure: Some(cause),
				},
			},
			Err(cause) => WitnessPublicationObservation::Reconcile {
				submission: Err(cause),
				names: Box::new(names),
				observation_failure: None,
			},
		}
	}

	fn check_directories(&self) -> Result<(), StageError> {
		let reader = self.original.stage.stage.reader;
		let job = reader.lease.job();
		job.recheck()?;
		reader
			.inventory
			.directory
			.as_ref()
			.ok_or(StageError::IdentityChanged)?
			.recheck(
				&job.directory.file,
				OsStr::new(crate::linux::job::STAGE),
				job.root.mount,
			)?;
		self.original.stage.lane.recheck()?;
		Ok(())
	}

	fn inspect(&self) -> (WitnessPublicationNames, [Option<File>; 3]) {
		let reader = self.original.stage.stage.reader;
		let job = reader.lease.job();
		if self.check_directories().is_err() {
			return (WitnessPublicationNames::default(), [None, None, None]);
		}
		let (private_stage, stage) =
			observe_name(self.names.stage, self.names.stage_name, job.root.mount);
		let (protected_witness, witness) = observe_name(
			&job.directory.file,
			OsStr::from_bytes(&self.original.name),
			job.root.mount,
		);
		let (public_target, target) =
			observe_name(&job.root.directory, self.names.target_name, job.root.mount);
		if self.check_directories().is_err() {
			return (WitnessPublicationNames::default(), [None, None, None]);
		}
		(
			WitnessPublicationNames {
				private_stage,
				protected_witness,
				public_target,
			},
			[stage, witness, target],
		)
	}

	fn confirm(
		&self,
		names: &WitnessPublicationNames,
		named_files: &[Option<File>; 3],
		renamed: bool,
	) -> Result<SourceObservation, StageError> {
		use WitnessPublicationName::{Absent, Regular};
		let original = self.original.stamp;
		let reader = self.original.stage.stage.reader;
		let job = reader.lease.job();
		let mount = job.root.mount;
		let held = &self.original.stage.stage.file.file;
		let current =
			SourceObservation::capture(&fs::fstat(held)?).map_err(StageError::ReadBack)?;
		let Regular(target) = names.public_target else {
			return Err(StageError::IdentityChanged);
		};
		let Regular(witness) = names.protected_witness else {
			return Err(StageError::IdentityChanged);
		};
		current.recheck(witness).map_err(StageError::ReadBack)?;
		if current.link_count() != 2 || mount_id(held)? != mount {
			return Err(StageError::IdentityChanged);
		}
		if renamed {
			if names.private_stage != Absent || !same_after_rename(original, current) {
				return Err(StageError::IdentityChanged);
			}
			current.recheck(target).map_err(StageError::ReadBack)?;
		} else {
			let Regular(stage) = names.private_stage else {
				return Err(StageError::IdentityChanged);
			};
			if target.identity() == original.identity() || target.link_count() == 0 {
				return Err(StageError::IdentityChanged);
			}
			original.recheck(current).map_err(StageError::ReadBack)?;
			current.recheck(stage).map_err(StageError::ReadBack)?;
		}
		check_aliases(&self.original.aliases, current, mount)?;
		check_no_visible_attributes(held)?;
		check_logical_eof(held, current.len()).map_err(StageError::ReadBack)?;
		let after = SourceObservation::capture(&fs::fstat(held)?).map_err(StageError::ReadBack)?;
		current.recheck(after).map_err(StageError::ReadBack)?;
		let (actual, _holds) = self.inspect();
		if !names.agrees(actual) {
			return Err(StageError::IdentityChanged);
		}
		for (observed, file) in [
			names.private_stage,
			names.protected_witness,
			names.public_target,
		]
		.into_iter()
		.zip(named_files)
		{
			if let (Regular(observed), Some(file)) = (observed, file) {
				let current =
					SourceObservation::capture(&fs::fstat(file)?).map_err(StageError::ReadBack)?;
				observed.recheck(current).map_err(StageError::ReadBack)?;
			}
		}
		if self.check_directories().is_err() {
			return Err(StageError::IdentityChanged);
		}
		Ok(target)
	}
}

fn observe_name(
	directory: &File,
	name: &OsStr,
	mount: u64,
) -> (WitnessPublicationName, Option<File>) {
	use WitnessPublicationName::{Absent, Regular, Unobserved};
	match open_path(directory, name) {
		Ok(Some(file)) => {
			if mount_id(&file).ok() != Some(mount) {
				return (Unobserved, None);
			}
			let Some(stamp) = fs::fstat(&file)
				.ok()
				.and_then(|stat| SourceObservation::capture(&stat).ok())
			else {
				return (Unobserved, None);
			};
			(Regular(stamp), Some(file))
		}
		Ok(None) => (Absent, None),
		Err(_) => (Unobserved, None),
	}
}

fn same_after_rename(before: SourceObservation, after: SourceObservation) -> bool {
	after.identity() == before.identity()
		&& after.len() == before.len()
		&& after.mode() == before.mode()
		&& after.owner() == before.owner()
		&& after.group() == before.group()
		&& after.modified_at() == before.modified_at()
		&& after.link_count() == before.link_count()
}
