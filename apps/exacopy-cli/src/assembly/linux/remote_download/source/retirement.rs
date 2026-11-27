use std::time::{Duration, Instant};

use exacopy_endpoint::connection_retry::{ConnectionAttempt, ConnectionBinding, RetryError};
use exacopy_sftp::SftpSourceError;
use exacopy_ssh::ReadOnlySftp;

use super::route_lifetime::observe_before;
use super::{
	BoundRoute, RemoteGrant, RemoteRouteCloseError, SourceOwner, Supervisor, route_refusal,
};

// The inner pump allows twenty seconds for FIN exchange. Its pinned smoltcp
// uses ten more seconds for TIME-WAIT. Leave a small scheduling margin without
// renewing the original grant.
const EMBEDDED_CLOSE_LIMIT: Duration = Duration::from_secs(32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::assembly::linux::remote_download) enum RetirementCheck {
	Live,
	VerifiedSource,
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
		matches!(
			self,
			Self::DataReadDeadline | Self::DataReadDeadlineWithRouteRefusal
		) && matches!(route, BoundRoute::Direct)
	}

	fn graceful_embedded(self, route: &BoundRoute<'_>) -> bool {
		self == Self::VerifiedSource && matches!(route, BoundRoute::Embedded { .. })
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
		let graceful = binding_check.is_ok() && check.graceful_embedded(&self.route);
		let task = &self.transport;
		let close = if graceful {
			let result = close_original_embedded(&self.supervisor, session).await;
			task.stop();
			result
		} else {
			task.stop();
			drop(session);
			Ok(())
		};
		let route = task.join().await.and(close);
		if (direct_read_deadline || graceful) && binding_check.is_ok() && route.is_ok() {
			binding_check = check_retired_generation(&self.supervisor, self.attempt, binding);
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
		// A held data deadline fences the exact direct socket. That socket
		// cannot change its authenticated peer as it closes.
		return check_retired_generation(supervisor, attempt, binding);
	}
	if check == RetirementCheck::DataReadDeadlineWithRouteRefusal || !active {
		return Err(route_refusal());
	}
	route.check()?;
	supervisor.observe(|retry, now| retry.check_completion(now, binding))
}

async fn close_original_embedded(
	supervisor: &Supervisor,
	session: ReadOnlySftp,
) -> Result<(), RemoteRouteCloseError> {
	let deadline = embedded_close_deadline(Instant::now(), supervisor.grant.deadline())
		.ok_or(RemoteRouteCloseError::GracefulCloseUnconfirmed)?;
	let deadline = tokio::time::Instant::from_std(deadline);
	await_embedded_shutdown(
		&supervisor.grant,
		deadline,
		session.disconnect_before(deadline),
	)
	.await
}

async fn await_embedded_shutdown(
	grant: &RemoteGrant,
	deadline: tokio::time::Instant,
	shutdown: impl Future<Output = Result<(), exacopy_ssh::Error>>,
) -> Result<(), RemoteRouteCloseError> {
	tokio::select! {
		biased;
		() = grant.wait_revoked() => Err(RemoteRouteCloseError::GracefulCloseUnconfirmed),
		result = observe_before(deadline, shutdown) => match result {
			Some(Ok(())) => Ok(()),
			None | Some(Err(_)) => Err(RemoteRouteCloseError::GracefulCloseUnconfirmed),
		},
	}
}

fn embedded_close_deadline(now: Instant, grant: Instant) -> Option<Instant> {
	let deadline = now.checked_add(EMBEDDED_CLOSE_LIMIT)?.min(grant);
	(now < deadline).then_some(deadline)
}

fn check_retired_generation(
	supervisor: &Supervisor,
	attempt: ConnectionAttempt,
	binding: ConnectionBinding,
) -> Result<(), RetryError> {
	// A stopped route cannot supply a live observation. The caller retains
	// its exact route owner and separately requires actual retirement.
	if binding.attempt() != attempt {
		return Err(RetryError::StaleWork);
	}
	supervisor.observe(|retry, now| retry.check_completion(now, binding))
}

#[cfg(test)]
mod tests;
