use exacopy_wireguard::stack::PumpError;

use super::{
	Arc, AsyncMutex, RemoteGrant, RemoteRouteCloseError, Retirement, RouteLease, RouteTask,
	RouteWake, StopOnExit, TokioInstant,
};

impl RouteTask {
	pub(in super::super) fn spawn_draining<E: Send + 'static>(
		lease: RouteLease,
		wake: RouteWake,
		grant: Arc<RemoteGrant>,
		work: impl Future<Output = Result<(), PumpError<E>>> + Send + 'static,
	) -> Self {
		let on_exit = StopOnExit {
			activity: lease.activity(),
			wake: wake.clone(),
		};
		let worker = tokio::spawn(async move {
			let stop = &on_exit;
			tokio::pin!(work);
			let completion = tokio::select! {
				biased;
				() = stop.activity.wait_stopped() => None,
				() = grant.wait_revoked() => None,
				() = tokio::time::sleep_until(TokioInstant::from_std(grant.deadline())) => None,
				result = work.as_mut() => Some(result),
			};
			if let Some(result) = completion {
				return result.map_err(|_| RemoteRouteCloseError::WorkerFailed);
			}
			stop.activity.stop();
			stop.wake.cancel();
			// Keep polling the actual driver after fencing its egress. A
			// successful join now observes that it finished and dropped its
			// owned UDP/TCP pump, rather than only observing cancellation.
			match work.await {
				Ok(()) | Err(PumpError::RouteRevoked | PumpError::Cancelled) => Ok(()),
				Err(_) => Err(RemoteRouteCloseError::WorkerFailed),
			}
		});
		Self {
			lease,
			wake,
			abort: worker.abort_handle(),
			retirement: AsyncMutex::new(Retirement {
				worker,
				direct_close: None,
				outcome: None,
			}),
		}
	}
}

#[cfg(test)]
mod tests {
	use std::future::poll_fn;
	use std::num::{NonZeroU64, NonZeroU128};
	use std::task::Poll;
	use std::time::{Duration, Instant};

	use exacopy_journal::remote_download::RemoteScopeDigest;
	use exacopy_wireguard::protocol::PeerBinding;
	use exacopy_wireguard::stack::{PumpError, RouteRevocation};
	use tokio::sync::oneshot;

	use super::{Arc, RemoteGrant, RemoteRouteCloseError, RouteLease, RouteTask, RouteWake};

	fn grant() -> Arc<RemoteGrant> {
		Arc::new(
			RemoteGrant::new(
				RemoteScopeDigest::from_bytes([1; 32]),
				[2; 32],
				Instant::now() + Duration::from_secs(60),
			)
			.unwrap(),
		)
	}

	fn wake() -> RouteWake {
		RouteWake::Embedded(RouteRevocation::new(PeerBinding {
			revision: [3; 32],
			actor: NonZeroU128::MIN,
			generation: NonZeroU64::MIN,
		}))
	}

	#[tokio::test]
	async fn worker_join_waits_for_fenced_pump_and_keeps_failure_sticky() {
		for expected_stop in [true, false] {
			let lease = RouteLease::new();
			let actor = lease.activity();
			let (started, starting) = oneshot::channel();
			let (drained, draining) = oneshot::channel();
			let task = RouteTask::spawn_draining(lease, wake(), grant(), async move {
				started.send(()).unwrap();
				draining.await.unwrap();
				if expected_stop {
					Err(PumpError::<()>::RouteRevoked)
				} else {
					Err(PumpError::<()>::Deadline)
				}
			});
			starting.await.unwrap();
			task.stop();
			assert!(!actor.is_active());

			let waiting = task.join();
			tokio::pin!(waiting);
			poll_fn(|cx| {
				assert!(waiting.as_mut().poll(cx).is_pending());
				Poll::Ready(())
			})
			.await;
			drained.send(()).unwrap();
			let expected = if expected_stop {
				Ok(())
			} else {
				Err(RemoteRouteCloseError::WorkerFailed)
			};
			assert_eq!(waiting.await, expected);
			assert_eq!(task.join().await, expected);
		}
	}
}
