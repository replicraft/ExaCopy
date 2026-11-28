use std::cell::Cell;
use std::error::Error;
use std::fmt;

use exacopy_journal::windows_bootstrap::{WindowsBootstrapFileIdentity, WindowsBootstrapPrefix};
use exacopy_journal::windows_capture::{WindowsCapturePrefix, WindowsCaptureRoles};

use super::{WindowsCaptureError, WindowsCaptureSelectionReceipt, WindowsFreshCaptureReport};

/// Last capture-ledger boundary confirmed on the original held sibling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsCaptureCheckpointProgress {
	/// Exact native identity of the private stage directory.
	pub stage_directory: WindowsBootstrapFileIdentity,
	/// Exact native identity of the private stage payload.
	pub stage_payload: WindowsBootstrapFileIdentity,
	/// Signed prepared frame and any subsequently confirmed signed ranges.
	pub prefix: WindowsCapturePrefix,
}

/// Historical observations reached before the invocation failed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowsCaptureProgress {
	/// The first native operation that could mutate the job was invoked.
	///
	/// This is conservative. The operation may have refused before submission,
	/// or there may be additional physical bytes beyond the last confirmed head.
	pub local_changes_may_exist: bool,
	/// Independent selection successfully retained by the caller, if reached.
	pub selection: Option<WindowsCaptureSelectionReceipt>,
	/// Confirmed V1 append, barriers and final native V1 handoff checks.
	pub bootstrap: Option<WindowsBootstrapPrefix>,
	/// Last confirmed signed ledger boundary and observed private stage IDs.
	pub checkpoint: Option<WindowsCaptureCheckpointProgress>,
	/// Complete source and stage measurements and source EOF and file closure.
	pub measured: Option<WindowsFreshCaptureReport>,
	/// The native callback returned with its final custody and EOF checks satisfied.
	pub native_closeout_confirmed: bool,
	/// The original SSH transport shut down and its exact TCP socket dropped.
	pub route_shutdown_confirmed: bool,
}

/// A refused or uncertain invocation, with its original cause and known progress.
///
/// The progress describes observations already made. It grants no permission
/// to resume or mutate the retained files.
#[derive(Debug)]
pub struct WindowsCaptureFailure(Box<FailedCapture>);

#[derive(Debug)]
struct FailedCapture {
	cause: WindowsCaptureError,
	progress: WindowsCaptureProgress,
}

impl WindowsCaptureFailure {
	/// The original refused or uncertain boundary.
	#[must_use]
	pub fn cause(&self) -> &WindowsCaptureError {
		&self.0.cause
	}

	/// Confirmed historical evidence and conservative mutation status.
	#[must_use]
	pub fn progress(&self) -> &WindowsCaptureProgress {
		&self.0.progress
	}
}

impl fmt::Display for WindowsCaptureFailure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.cause().fmt(formatter)
	}
}

impl Error for WindowsCaptureFailure {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(self.cause())
	}
}

/// Invocation-owned journal of observations that outlives lent futures.
#[derive(Default)]
pub(super) struct Progress(Cell<WindowsCaptureProgress>);

impl Progress {
	pub(super) fn update(&self, update: impl FnOnce(&mut WindowsCaptureProgress)) {
		let mut snapshot = self.0.get();
		update(&mut snapshot);
		self.0.set(snapshot);
	}

	pub(super) fn checkpoint(&self, roles: WindowsCaptureRoles, prefix: WindowsCapturePrefix) {
		self.update(|progress| {
			progress.checkpoint = Some(WindowsCaptureCheckpointProgress {
				stage_directory: roles.stage_directory,
				stage_payload: roles.stage_payload,
				prefix,
			});
		});
	}

	pub(super) fn failure(&self, cause: WindowsCaptureError) -> WindowsCaptureFailure {
		WindowsCaptureFailure(Box::new(FailedCapture {
			cause,
			progress: self.0.get(),
		}))
	}
}

#[cfg(test)]
mod tests;
