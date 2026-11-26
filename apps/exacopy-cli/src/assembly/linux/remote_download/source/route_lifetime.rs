use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_ssh::SshSessionCancellation;
#[cfg(feature = "experimental-ssh-wireguard")]
use exacopy_wireguard::stack::RouteRevocation;
use tokio::sync::{Mutex as AsyncMutex, Notify, oneshot};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::Instant as TokioInstant;

use super::RemoteGrant;

const TRANSPORT_CLOSE_LIMIT: Duration = Duration::from_secs(2);

/// Serializes retirement with the actual nonblocking transport operation.
pub(super) struct RouteActivity {
	active: Mutex<RouteState>,
	stopped: Notify,
}

struct RouteState {
	active: bool,
	connect_deadline: Option<Instant>,
}

impl RouteState {
	fn current(&self, now: Instant) -> bool {
		self.active && self.connect_deadline.is_none_or(|deadline| now < deadline)
	}
}

impl RouteActivity {
	pub(super) fn with_grant<T>(
		&self,
		grant: &RemoteGrant,
		scope: RemoteScopeDigest,
		operation: impl FnOnce(bool) -> T,
	) -> T {
		let Ok(_grant) = grant.source_lock(scope) else {
			return operation(false);
		};
		let Ok(active) = self.active.lock() else {
			return operation(false);
		};
		let now = Instant::now();
		operation(active.current(now) && now < grant.deadline())
	}

	pub(super) fn is_active(&self) -> bool {
		self.active
			.lock()
			.is_ok_and(|state| state.current(Instant::now()))
	}

	fn finish_connection(&self) -> bool {
		let Ok(mut state) = self.active.lock() else {
			return false;
		};
		if !state.current(Instant::now()) {
			return false;
		}
		state.connect_deadline = None;
		true
	}

	pub(super) fn stop(&self) {
		{
			let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
			active.active = false;
		}
		self.stopped.notify_waiters();
	}

	async fn wait_stopped(&self) {
		let notice = self.stopped.notified();
		tokio::pin!(notice);
		notice.as_mut().enable();
		if self.is_active() {
			notice.await;
		}
	}
}

/// Unique route lifetime until the worker and scoped source assume ownership.
pub(super) struct RouteLease {
	activity: Arc<RouteActivity>,
}

impl RouteLease {
	#[cfg(test)]
	pub(super) fn new() -> Self {
		Self::with_deadline(None)
	}

	pub(super) fn connecting(deadline: Instant) -> Self {
		Self::with_deadline(Some(deadline))
	}

	fn with_deadline(connect_deadline: Option<Instant>) -> Self {
		Self {
			activity: Arc::new(RouteActivity {
				active: Mutex::new(RouteState {
					active: true,
					connect_deadline,
				}),
				stopped: Notify::new(),
			}),
		}
	}

	pub(super) fn activity(&self) -> Arc<RouteActivity> {
		Arc::clone(&self.activity)
	}
}

impl Drop for RouteLease {
	fn drop(&mut self) {
		self.activity.stop();
	}
}

#[derive(Clone)]
pub(super) enum RouteWake {
	Ssh(SshSessionCancellation),
	#[cfg(feature = "experimental-ssh-wireguard")]
	Embedded(RouteRevocation),
}

impl RouteWake {
	fn cancel(&self) {
		match self {
			Self::Ssh(session) => session.cancel(),
			#[cfg(feature = "experimental-ssh-wireguard")]
			Self::Embedded(route) => route.revoke(),
		}
	}
}

struct StopOnExit {
	activity: Arc<RouteActivity>,
	wake: RouteWake,
}

impl Drop for StopOnExit {
	fn drop(&mut self) {
		self.activity.stop();
		self.wake.cancel();
	}
}

/// Coordinates the exact transport worker and its independent publication grant.
pub(super) struct RouteTask {
	lease: RouteLease,
	wake: RouteWake,
	retirement: AsyncMutex<Retirement>,
	abort: AbortHandle,
}

struct Retirement {
	worker: JoinHandle<()>,
	direct_close: Option<oneshot::Receiver<()>>,
	outcome: Option<Result<(), RemoteRouteCloseError>>,
}

/// Why stopping the old route did not establish its physical retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteRouteCloseError {
	/// The first observer was dropped before it confirmed teardown.
	Unobserved,
	/// The carrier worker did not exit within the teardown budget.
	WorkerTimeout,
	/// The carrier worker exited unsuccessfully.
	WorkerFailed,
	/// The direct socket close was not acknowledged within the teardown budget.
	SocketTimeout,
	/// The direct socket close acknowledgment was lost.
	SocketUnconfirmed,
}

impl fmt::Display for RemoteRouteCloseError {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		out.write_str(match self {
			Self::Unobserved => "route retirement was not observed",
			Self::WorkerTimeout => "route worker did not stop within its deadline",
			Self::WorkerFailed => "route worker did not exit cleanly",
			Self::SocketTimeout => "direct socket close was not observed within its deadline",
			Self::SocketUnconfirmed => "direct socket close acknowledgment was lost",
		})
	}
}

impl std::error::Error for RemoteRouteCloseError {}

impl Retirement {
	async fn observe_once(&mut self) -> Result<(), RemoteRouteCloseError> {
		if let Some(outcome) = self.outcome {
			return outcome;
		}
		// Reserve the only observation before awaiting. If this future is
		// abandoned, later observers must retain the inconclusive outcome.
		self.outcome = Some(Err(RemoteRouteCloseError::Unobserved));
		let outcome = self.observe().await;
		self.outcome = Some(outcome);
		outcome
	}

	async fn observe(&mut self) -> Result<(), RemoteRouteCloseError> {
		let deadline = TokioInstant::now() + TRANSPORT_CLOSE_LIMIT;
		match observe_before(deadline, &mut self.worker).await {
			Some(Ok(())) => {}
			Some(Err(_)) => return Err(RemoteRouteCloseError::WorkerFailed),
			None => {
				self.worker.abort();
				return Err(RemoteRouteCloseError::WorkerTimeout);
			}
		}
		if let Some(closed) = &mut self.direct_close {
			let deadline = TokioInstant::now() + TRANSPORT_CLOSE_LIMIT;
			match observe_before(deadline, closed).await {
				Some(Ok(())) => {}
				Some(Err(_)) => return Err(RemoteRouteCloseError::SocketUnconfirmed),
				None => return Err(RemoteRouteCloseError::SocketTimeout),
			}
		}
		Ok(())
	}
}

async fn observe_before<T>(
	deadline: TokioInstant,
	observation: impl Future<Output = T>,
) -> Option<T> {
	let result = tokio::time::timeout_at(deadline, observation).await.ok()?;
	// Tokio can return the inner result when both the observation and timer
	// are ready. A late observation cannot confirm this attempt's retirement.
	(TokioInstant::now() < deadline).then_some(result)
}

impl RouteTask {
	pub(super) fn spawn(
		lease: RouteLease,
		wake: RouteWake,
		grant: Arc<RemoteGrant>,
		direct_close: Option<oneshot::Receiver<()>>,
		work: impl Future<Output = ()> + Send + 'static,
	) -> Self {
		let on_exit = StopOnExit {
			activity: lease.activity(),
			wake: wake.clone(),
		};
		let worker = tokio::spawn(async move {
			let stop = &on_exit;
			tokio::select! {
				biased;
				() = stop.activity.wait_stopped() => {}
				() = grant.wait_revoked() => {}
				() = tokio::time::sleep_until(tokio::time::Instant::from_std(grant.deadline())) => {}
				() = work => {}
			}
		});
		Self {
			lease,
			wake,
			abort: worker.abort_handle(),
			retirement: AsyncMutex::new(Retirement {
				worker,
				direct_close,
				outcome: None,
			}),
		}
	}

	pub(super) fn is_active(&self) -> bool {
		self.lease.activity.is_active()
	}

	pub(super) fn finish_connection(&self) -> bool {
		self.lease.activity.finish_connection()
	}

	pub(super) fn stop(&self) {
		self.lease.activity.stop();
		self.wake.cancel();
	}

	pub(super) async fn join(&self) -> Result<(), RemoteRouteCloseError> {
		self.retirement.lock().await.observe_once().await
	}
}

impl Drop for RouteTask {
	fn drop(&mut self) {
		self.stop();
		self.abort.abort();
	}
}

#[cfg(test)]
mod tests {
	use std::future::{pending, poll_fn};
	use std::sync::mpsc;
	use std::task::Poll;
	use std::thread;

	use super::*;

	#[test]
	fn a_route_local_stop_waits_for_the_inflight_operation_and_fences_later_effects() {
		let scope = RemoteScopeDigest::from_bytes([1; 32]);
		let grant =
			RemoteGrant::new(scope, [2; 32], Instant::now() + Duration::from_secs(60)).unwrap();
		let lease = RouteLease::new();
		let route = lease.activity();
		let (entered, operation_entered) = mpsc::channel();
		let (release, operation_release) = mpsc::channel();
		let (starting, stop_started) = mpsc::channel();
		let (stopped, stop_completed) = mpsc::channel();
		thread::scope(|scope_thread| {
			let active = &route;
			let grant = &grant;
			scope_thread.spawn(move || {
				active.with_grant(grant, scope, |current| {
					assert!(current);
					entered.send(()).unwrap();
					operation_release
						.recv_timeout(Duration::from_secs(5))
						.unwrap();
				});
			});
			operation_entered
				.recv_timeout(Duration::from_secs(5))
				.unwrap();
			scope_thread.spawn(move || {
				starting.send(()).unwrap();
				drop(lease);
				stopped.send(()).unwrap();
			});
			stop_started.recv_timeout(Duration::from_secs(5)).unwrap();
			let blocked = stop_completed.recv_timeout(Duration::from_millis(30));
			release.send(()).unwrap();
			assert!(matches!(blocked, Err(mpsc::RecvTimeoutError::Timeout)));
			stop_completed.recv_timeout(Duration::from_secs(5)).unwrap();
		});
		assert!(!route.with_grant(&grant, scope, |current| current));
		assert!(grant.check_source(scope).is_ok());
	}

	#[tokio::test]
	async fn waiting_for_an_already_stopped_route_does_not_lose_the_wake() {
		let lease = RouteLease::new();
		let route = lease.activity();
		drop(lease);
		tokio::time::timeout(Duration::from_secs(1), route.wait_stopped())
			.await
			.unwrap();
	}

	#[tokio::test]
	async fn repeated_retirement_preserves_worker_timeout() {
		let mut retirement = Retirement {
			worker: tokio::spawn(pending()),
			direct_close: None,
			outcome: None,
		};
		for _ in 0..2 {
			assert_eq!(
				retirement.observe_once().await,
				Err(RemoteRouteCloseError::WorkerTimeout)
			);
		}
	}

	#[tokio::test]
	async fn late_socket_close_cannot_recover_a_retirement_timeout() {
		let (close, observed) = oneshot::channel();
		let mut retirement = Retirement {
			worker: tokio::spawn(async {}),
			direct_close: Some(observed),
			outcome: None,
		};
		assert_eq!(
			retirement.observe_once().await,
			Err(RemoteRouteCloseError::SocketTimeout)
		);
		close.send(()).unwrap();
		assert_eq!(
			retirement.observe_once().await,
			Err(RemoteRouteCloseError::SocketTimeout)
		);
	}

	#[tokio::test]
	async fn dropping_first_retirement_observation_cannot_confirm_a_later_retry() {
		let (close, observed) = oneshot::channel();
		let mut retirement = Retirement {
			worker: tokio::spawn(async {}),
			direct_close: Some(observed),
			outcome: None,
		};
		{
			let mut first = std::pin::pin!(retirement.observe_once());
			poll_fn(|cx| {
				assert!(first.as_mut().poll(cx).is_pending());
				Poll::Ready(())
			})
			.await;
		}
		close.send(()).unwrap();
		assert_eq!(
			retirement.observe_once().await,
			Err(RemoteRouteCloseError::Unobserved)
		);
	}

	#[tokio::test]
	async fn confirmed_socket_close_remains_confirmed_on_a_second_join() {
		let (close, observed) = oneshot::channel();
		let mut retirement = Retirement {
			worker: tokio::spawn(async {}),
			direct_close: Some(observed),
			outcome: None,
		};
		close.send(()).unwrap();
		assert_eq!(retirement.observe_once().await, Ok(()));
		assert_eq!(retirement.observe_once().await, Ok(()));
	}

	#[tokio::test]
	async fn ready_observations_cannot_win_after_the_absolute_deadline() {
		let deadline = TokioInstant::now();
		let mut worker = tokio::spawn(async {});
		tokio::time::timeout(TRANSPORT_CLOSE_LIMIT, async {
			while !worker.is_finished() {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
		let (acknowledge, closed) = oneshot::channel();
		acknowledge.send(()).unwrap();
		assert!(observe_before(deadline, &mut worker).await.is_none());
		assert!(observe_before(deadline, closed).await.is_none());
	}

	#[cfg(feature = "experimental-ssh-wireguard")]
	#[tokio::test]
	async fn grant_revocation_joins_embedded_worker_without_restoring_authority() {
		use std::num::{NonZeroU64, NonZeroU128};

		use exacopy_wireguard::protocol::PeerBinding;

		let scope = RemoteScopeDigest::from_bytes([1; 32]);
		let grant = Arc::new(
			RemoteGrant::new(scope, [2; 32], Instant::now() + Duration::from_secs(60)).unwrap(),
		);
		let lease = RouteLease::new();
		let activity = lease.activity();
		let revocation = RouteRevocation::new(PeerBinding {
			revision: [3; 32],
			actor: NonZeroU128::MIN,
			generation: NonZeroU64::MIN,
		});
		let task = RouteTask::spawn(
			lease,
			RouteWake::Embedded(revocation),
			Arc::clone(&grant),
			None,
			pending(),
		);
		assert!(activity.with_grant(&grant, scope, |current| current));
		grant.revoke();
		assert_eq!(task.join().await, Ok(()));
		assert_eq!(task.join().await, Ok(()));
		assert!(!task.is_active());
		assert!(grant.check_source(scope).is_err());
		assert!(!activity.with_grant(&grant, scope, |current| current));
	}
}
