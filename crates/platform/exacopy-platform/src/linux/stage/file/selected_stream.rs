use super::{ClosedStage, SourceObservation, StageError};
use crate::linux::stage::selected_stream::SelectedStreamView;

impl ClosedStage<'_> {
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
