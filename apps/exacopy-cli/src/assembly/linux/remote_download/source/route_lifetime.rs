use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_ssh::SshSessionCancellation;
#[cfg(feature = "experimental-ssh-wireguard")]
use exacopy_wireguard::stack::RouteRevocation;
use tokio::sync::{Notify, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

use super::RemoteGrant;

const TRANSPORT_CLOSE_LIMIT: Duration = Duration::from_secs(2);

/// Serializes retirement with the actual nonblocking transport operation.
pub(super) struct RouteActivity {
	active: Mutex<bool>,
	stopped: Notify,
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
		operation(*active && Instant::now() < grant.deadline())
	}

	pub(super) fn is_active(&self) -> bool {
		self.active.lock().is_ok_and(|active| *active)
	}

	pub(super) fn stop(&self) {
		{
			let mut active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
			*active = false;
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
	pub(super) fn new() -> Self {
		Self {
			activity: Arc::new(RouteActivity {
				active: Mutex::new(true),
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
	worker: Mutex<Option<JoinHandle<()>>>,
	direct_close: Mutex<Option<oneshot::Receiver<()>>>,
	abort: AbortHandle,
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
			worker: Mutex::new(Some(worker)),
			direct_close: Mutex::new(direct_close),
		}
	}

	pub(super) fn is_active(&self) -> bool {
		self.lease.activity.is_active()
	}

	pub(super) fn stop(&self) {
		self.lease.activity.stop();
		self.wake.cancel();
	}

	pub(super) async fn join(&self) -> bool {
		let work = self
			.worker
			.lock()
			.unwrap_or_else(PoisonError::into_inner)
			.take();
		if let Some(mut work) = work
			&& tokio::time::timeout(TRANSPORT_CLOSE_LIMIT, &mut work)
				.await
				.is_err()
		{
			work.abort();
			return false;
		}
		let direct_close = self
			.direct_close
			.lock()
			.unwrap_or_else(PoisonError::into_inner)
			.take();
		match direct_close {
			Some(closed) => matches!(
				tokio::time::timeout(TRANSPORT_CLOSE_LIMIT, closed).await,
				Ok(Ok(()))
			),
			None => true,
		}
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
	use std::sync::mpsc;
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
}
