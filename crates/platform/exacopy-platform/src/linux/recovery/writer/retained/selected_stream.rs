use super::{RetainedStage, SourceObservation, StageError};
use crate::linux::stage::selected_stream::SelectedStreamView;
use crate::linux::stage::{FILE_MODE, PublicationNames, check_named_file};

impl RetainedStage<'_> {
	pub(in crate::linux) fn selected_stream_names(&self) -> PublicationNames<'_> {
		PublicationNames {
			stage: &self.directory,
			stage_name: &self.inventory.stage_name,
			destination: self.inventory.job.root,
			target_name: &self.inventory.target_name,
		}
	}

	pub(in crate::linux) fn check_selected_stream_directory(&self) -> Result<(), StageError> {
		self.inventory.job.recheck()?;
		self.recheck_directory()
	}

	pub(in crate::linux) fn selected_stream_view(
		&self,
	) -> Result<SelectedStreamView<'_>, StageError> {
		self.check_selected_stream_directory()?;
		let root = self.inventory.job.root;
		let named = check_named_file(
			&self.directory,
			&self.inventory.stage_name,
			self.stage.identity(),
			root.mount,
			FILE_MODE,
		)?;
		let expected = self.stage.observation();
		expected
			.recheck(SourceObservation::capture(&named).map_err(StageError::ReadBack)?)
			.map_err(StageError::ReadBack)?;
		Ok(SelectedStreamView {
			file: &self.stage.file,
			expected,
			destination: root.identity(),
			stage_directory: self.directory_identity,
			binding: self.binding,
			mount: root.mount,
		})
	}
}
