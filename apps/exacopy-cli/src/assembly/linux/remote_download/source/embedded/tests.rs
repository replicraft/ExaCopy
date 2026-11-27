use std::cell::Cell;
use std::future::{pending, poll_fn};
use std::num::NonZeroU64;
use std::task::Poll;

use exacopy_wireguard::stack::PumpError;
use tokio::sync::oneshot;

use super::*;

fn task(work: impl Future<Output = Result<(), PumpError<()>>> + Send + 'static) -> RouteTask {
	let scope = RemoteScopeDigest::from_bytes([1; 32]);
	let grant = Arc::new(
		RemoteGrant::new(scope, [2; 32], Instant::now() + Duration::from_secs(60)).unwrap(),
	);
	let revocation = RouteRevocation::new(PeerBinding {
		revision: [3; 32],
		actor: NonZeroU128::MIN,
		generation: NonZeroU64::MIN,
	});
	RouteTask::spawn_draining(
		RouteLease::new(),
		RouteWake::Embedded(revocation),
		grant,
		work,
	)
}

#[tokio::test]
async fn denied_authentication_waits_for_the_fenced_driver_and_survives_late_cancel() {
	let (release, drain) = oneshot::channel();
	let task = task(async move {
		drain.await.unwrap();
		Err(PumpError::RouteRevoked)
	});
	let cancelled = Cell::new(false);
	let refused = run_then_retire(
		&task,
		async { Err::<(), _>(EmbeddedConnectError::Ssh(SshError::Authentication)) },
		|| cancelled.get(),
	);
	let mut refused = std::pin::pin!(refused);
	poll_fn(|context| {
		assert!(refused.as_mut().poll(context).is_pending());
		Poll::Ready(())
	})
	.await;
	assert!(!task.is_active());
	cancelled.set(true);
	release.send(()).unwrap();
	assert!(matches!(
		refused.await,
		Err(EmbeddedConnectFailure {
			cause: EmbeddedConnectError::Ssh(SshError::Authentication),
			cancelled_at_refusal: Some(false),
			route_failure: None,
		})
	));
	assert_eq!(task.join().await, Ok(()));
}

#[tokio::test]
async fn refused_binding_keeps_both_the_refusal_and_failed_retirement() {
	let task = task(async { Err(PumpError::Deadline) });
	let outcome = run_then_retire(
		&task,
		async { Err::<(), _>(EmbeddedConnectError::Retry(RetryError::StaleWork)) },
		|| false,
	)
	.await;
	assert!(matches!(
		outcome,
		Err(EmbeddedConnectFailure {
			cause: EmbeddedConnectError::Retry(RetryError::StaleWork),
			cancelled_at_refusal: Some(false),
			route_failure: Some(RemoteRouteCloseError::WorkerFailed),
		})
	));
	assert_eq!(task.join().await, Err(RemoteRouteCloseError::WorkerFailed));
}

#[tokio::test]
async fn timed_out_connection_preserves_a_worker_timeout() {
	let task = task(pending());
	let outcome = run_then_retire(
		&task,
		async { Err::<(), _>(EmbeddedConnectError::Timeout) },
		|| false,
	)
	.await;
	assert!(matches!(
		outcome,
		Err(EmbeddedConnectFailure {
			cause: EmbeddedConnectError::Timeout,
			cancelled_at_refusal: Some(false),
			route_failure: Some(RemoteRouteCloseError::WorkerTimeout),
		})
	));
	assert_eq!(task.join().await, Err(RemoteRouteCloseError::WorkerTimeout));
}

#[tokio::test]
async fn worker_close_retains_the_consumers_exact_shutdown_decision() {
	let (release, drain) = oneshot::channel();
	let task = task(async move {
		drain.await.unwrap();
		Err(PumpError::RouteRevoked)
	});
	let outcome = run_then_retire(
		&task,
		async {
			task.stop();
			release.send(()).unwrap();
			assert_eq!(task.join().await, Ok(()));
			Ok(Err::<(), _>(
				RemoteRouteCloseError::GracefulCloseUnconfirmed,
			))
		},
		|| false,
	)
	.await
	.unwrap();
	assert_eq!(outcome.retirement, Ok(()));
	assert_eq!(
		outcome.outcome,
		Err(RemoteRouteCloseError::GracefulCloseUnconfirmed)
	);
}

#[tokio::test]
async fn consumer_early_refusal_retains_the_unconfirmed_worker_close() {
	let task = task(async { Err(PumpError::Deadline) });
	let outcome = run_then_retire(
		&task,
		async { Ok(Err::<(), _>(RetryError::StaleAdmission)) },
		|| false,
	)
	.await
	.unwrap();
	assert_eq!(outcome.outcome, Err(RetryError::StaleAdmission));
	assert_eq!(outcome.retirement, Err(RemoteRouteCloseError::WorkerFailed));
}
