use super::{ClosedStage, SourceObservation, StageError};
use crate::linux::stage::PublicationNames;
use crate::linux::stage::selected_stream::SelectedStreamView;

impl ClosedStage<'_> {
	pub(in crate::linux) fn selected_stream_names(&self) -> PublicationNames<'_> {
		let directory = self.location.directory;
		PublicationNames {
			stage: &directory.directory,
			stage_name: self.location.name.as_os_str(),
			destination: directory.root,
			target_name: self.location.target.as_os_str(),
		}
	}

	pub(in crate::linux) fn check_selected_stream_directory(&self) -> Result<(), StageError> {
		self.location.directory.check_current()
	}

	pub(in crate::linux) fn selected_stream_view(
		&self,
	) -> Result<SelectedStreamView<'_>, StageError> {
		if self.metadata_applied {
			return Err(StageError::MetadataMismatch);
		}
		self.check_current()?;
		let directory = self.location.directory;
		Ok(SelectedStreamView {
			file: &self.file,
			expected: SourceObservation::capture(&self.stat).map_err(StageError::ReadBack)?,
			destination: directory.root.identity(),
			stage_directory: directory.identity(),
			binding: self.location.binding,
			mount: directory.root.mount,
		})
	}
}
