use exacopy_endpoint::connection_retry::{ConnectionAttempt, ConnectionBinding, RetryError};
use exacopy_sftp::SftpSourceError;
use exacopy_ssh::ReadOnlySftp;

use super::{BoundRoute, RemoteRouteCloseError, SourceOwner, Supervisor, route_refusal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::assembly::linux::remote_download) enum RetirementCheck {
	Live,
	DataReadDeadline,
	DataReadDeadlineWithRouteRefusal,
}

impl RetirementCheck {
	pub(in crate::assembly::linux::remote_download) fn from_read_error(
		error: &SftpSourceError,
	) -> Self {
		match error {
			SftpSourceError::ReadTimeout => Self::DataReadDeadline,
			SftpSourceError::ReadTimeoutBinding(cause) if *cause == route_refusal() => {
				Self::DataReadDeadlineWithRouteRefusal
			}
			_ => Self::Live,
		}
	}

	fn direct_read_deadline(self, route: &BoundRoute<'_>) -> bool {
		self != Self::Live && matches!(route, BoundRoute::Direct)
	}
}

pub(in crate::assembly::linux::remote_download) struct SourceRetirement {
	pub(in crate::assembly::linux::remote_download) binding: Result<(), RetryError>,
	pub(in crate::assembly::linux::remote_download) route: Result<(), RemoteRouteCloseError>,
}

impl SourceOwner<'_> {
	pub(in crate::assembly::linux::remote_download) async fn retire(
		self,
		binding: ConnectionBinding,
		session: ReadOnlySftp,
		check: RetirementCheck,
	) -> SourceRetirement {
		let direct_read_deadline = check.direct_read_deadline(&self.route);
		let mut binding_check = check_before_stop(
			check,
			&self.route,
			&self.supervisor,
			self.attempt,
			binding,
			self.transport.is_active(),
		);
		let task = &self.transport;
		task.stop();
		drop(session);
		let route = task.join().await;
		if direct_read_deadline && binding_check.is_ok() && route.is_ok() {
			binding_check = check_stopped_direct(&self.supervisor, self.attempt, binding);
		}
		SourceRetirement {
			binding: binding_check,
			route,
		}
	}
}

fn check_before_stop(
	check: RetirementCheck,
	route: &BoundRoute<'_>,
	supervisor: &Supervisor,
	attempt: ConnectionAttempt,
	binding: ConnectionBinding,
	active: bool,
) -> Result<(), RetryError> {
	if check.direct_read_deadline(route) {
		return check_stopped_direct(supervisor, attempt, binding);
	}
	if check == RetirementCheck::DataReadDeadlineWithRouteRefusal || !active {
		return Err(route_refusal());
	}
	route.check()?;
	supervisor.observe(|retry, now| retry.check_completion(now, binding))
}

fn check_stopped_direct(
	supervisor: &Supervisor,
	attempt: ConnectionAttempt,
	binding: ConnectionBinding,
) -> Result<(), RetryError> {
	// The exact direct TCP socket was matched at authentication. It cannot
	// change peer on close. A data deadline fences that socket before it can
	// report a refused read. Only generation/authority remains checkable
	// here, and the caller must still await positive retirement.
	if binding.attempt() != attempt {
		return Err(RetryError::StaleWork);
	}
	supervisor.observe(|retry, now| retry.check_completion(now, binding))
}

#[cfg(test)]
mod tests;
