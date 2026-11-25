use super::{RetainedStage, StageError};
use crate::linux::stage::selected_stream::SelectedStreamView;

impl RetainedStage<'_> {
	pub(in crate::linux) fn selected_stream_view(
		&self,
	) -> Result<SelectedStreamView<'_>, StageError> {
		self.inventory.recheck()?;
		self.recheck_directory()?;
		let root = self.inventory.job.root;
		Ok(SelectedStreamView {
			file: &self.stage.file,
			expected: self.stage.observation(),
			destination: root.identity(),
			stage_directory: self.directory_identity,
			binding: self.binding,
			mount: root.mount,
		})
	}
}
