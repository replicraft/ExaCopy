use std::fmt;

use super::RemoteDownloadReplay;

impl fmt::Debug for RemoteDownloadReplay {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RemoteDownloadReplay")
			.field("boundary", &self.boundary)
			.field("job_prepared", &self.job_prepared)
			.field("stage_directory_prepared", &self.stage_directory_prepared)
			.field("attempts", &self.attempts)
			.field(
				"active_checkpoint_count",
				&self.active_checkpoints.as_ref().map(Vec::len),
			)
			.field("uncertainty", &self.uncertainty)
			.field("issue", &self.issue)
			.finish()
	}
}
