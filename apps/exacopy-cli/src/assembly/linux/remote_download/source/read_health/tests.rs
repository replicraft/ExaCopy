use std::num::{NonZeroU64, NonZeroU128};
use std::time::Duration;

use exacopy_endpoint::connection_retry::{
	ConnectionBinding, ConnectionFailure, FailureDecision, FailureSubject, ReconnectEvidence,
	RetryBlock, RetryDecision, RetryOwner, RetrySupervisor, TransientFailure, VerifiedHealth,
};

use super::*;

struct ExactRead {
	result: Result<(), SftpSourceError>,
}

impl CapturedReadAt for ExactRead {
	type Error = SftpSourceError;

	fn epoch(&self) -> SourceEpoch {
		SourceEpoch::new(NonZeroU64::MIN)
	}

	fn length(&self) -> u64 {
		1
	}

	fn max_window_bytes(&self) -> NonZeroUsize {
		NonZeroUsize::MIN
	}

	async fn read_exact_at(&mut self, _offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		bytes.fill(42);
		std::mem::replace(&mut self.result, Ok(()))
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		Ok(())
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		Ok(())
	}
}

fn admit(retry: &mut RetrySupervisor, now: Duration, epoch: NonZeroU64) -> ConnectionBinding {
	let RetryDecision::Start(attempt) = retry.poll(now).unwrap() else {
		panic!("the original invocation should be ready for one attempt");
	};
	retry
		.admit(
			now,
			attempt,
			ReconnectEvidence {
				route_checked_for: attempt,
				ssh_authenticated_for: attempt,
				source_checked_for: attempt,
				source_epoch: SourceEpoch::new(epoch),
			},
		)
		.unwrap()
}

fn fail_read(retry: &mut RetrySupervisor, now: Duration, binding: ConnectionBinding) -> Duration {
	let FailureDecision::WaitUntil { wake_at, .. } = retry
		.failure(
			now,
			FailureSubject::Connection(binding),
			ConnectionFailure::Transient {
				cause: TransientFailure::NonMutatingTimeout,
				jitter_sample: 0,
			},
		)
		.unwrap()
	else {
		panic!("an authorized held read timeout should schedule backoff");
	};
	wake_at
}

#[tokio::test]
async fn a_late_positive_window_resets_backoff_on_the_current_admitted_connection() {
	let lease = Duration::from_secs(60);
	let early = Duration::from_secs(10);
	let late = Duration::from_secs(30);
	for (online_for, read_result, window_length, expected_ms) in [
		(early, Ok(()), 1, 1_000),
		(late, Ok(()), 1, 500),
		(late, Ok(()), 0, 1_000),
		(late, Err(SftpSourceError::ReadTimeout), 1, 1_000),
	] {
		let mut retry = RetrySupervisor::new(RetryOwner::new(NonZeroU128::MIN), lease);
		let first = admit(&mut retry, Duration::ZERO, NonZeroU64::MIN);
		let due = fail_read(&mut retry, Duration::ZERO, first);
		let current = admit(&mut retry, due, NonZeroU64::MIN.saturating_add(1));
		let now = due + online_for;
		let expected_timeout = read_result.is_err();
		{
			let mut source = VerifiedReads::new(
				ExactRead {
					result: read_result,
				},
				|| retry.observe_health(now, current, VerifiedHealth::SuccessfulOperation),
			);
			source.recheck().await.unwrap();
			let mut buffer = [0];
			let result = source.read_exact_at(0, &mut buffer[..window_length]).await;
			if expected_timeout {
				assert!(matches!(result, Err(SftpSourceError::ReadTimeout)));
			} else {
				result.unwrap();
				source.finish().await.unwrap();
			}
		}
		assert_eq!(
			fail_read(&mut retry, now, current) - now,
			Duration::from_millis(expected_ms)
		);
		assert_eq!(
			retry.poll(lease),
			Err(RetryError::Blocked(RetryBlock::GrantExpired))
		);
	}
}

#[tokio::test]
async fn a_positive_window_cannot_reset_the_successor_through_a_stale_binding() {
	let mut retry =
		RetrySupervisor::new(RetryOwner::new(NonZeroU128::MIN), Duration::from_secs(60));
	let first = admit(&mut retry, Duration::ZERO, NonZeroU64::MIN);
	let due = fail_read(&mut retry, Duration::ZERO, first);
	let current = admit(&mut retry, due, NonZeroU64::MIN.saturating_add(1));
	let now = due + Duration::from_secs(30);
	let mut source = VerifiedReads::new(ExactRead { result: Ok(()) }, || {
		retry.observe_health(now, first, VerifiedHealth::SuccessfulOperation)
	});
	assert!(matches!(
		source.read_exact_at(0, &mut [0]).await,
		Err(SftpSourceError::Binding(RetryError::StaleWork))
	));
	assert_eq!(
		fail_read(&mut retry, now, current) - now,
		Duration::from_secs(1)
	);
}

#[cfg(feature = "experimental-ssh-wireguard")]
#[tokio::test]
async fn source_owner_requires_a_live_route_and_authority_before_updating_backoff() {
	use std::future;
	use std::sync::{Arc, Mutex};
	use std::time::Instant;

	use exacopy_endpoint::connection_retry::PermanentFailure;
	use exacopy_journal::remote_download::RemoteScopeDigest;
	use exacopy_wireguard::protocol::PeerBinding;
	use exacopy_wireguard::stack::RouteRevocation;

	use super::super::route_lifetime::{RouteLease, RouteTask, RouteWake};
	use super::super::{BoundRoute, RemoteGrant, SourceOwner, Supervisor, route_refusal};

	let scope = RemoteScopeDigest::from_bytes([1; 32]);
	let now = Instant::now();
	let grant = Arc::new(RemoteGrant::new(scope, [2; 32], now + Duration::from_secs(30)).unwrap());
	let start = now.checked_sub(Duration::from_secs(31)).unwrap();
	let budget = grant.remaining_from(start).unwrap();
	let mut retry = RetrySupervisor::new(RetryOwner::new(NonZeroU128::MIN), budget);
	let first = admit(&mut retry, Duration::ZERO, NonZeroU64::MIN);
	let due = fail_read(&mut retry, Duration::ZERO, first);
	let active = admit(&mut retry, due, NonZeroU64::MIN.saturating_add(1));
	let transport = Arc::new(RouteTask::spawn(
		RouteLease::new(),
		RouteWake::Embedded(RouteRevocation::new(PeerBinding {
			revision: [3; 32],
			actor: NonZeroU128::MIN,
			generation: active.attempt().generation(),
		})),
		Arc::clone(&grant),
		None,
		future::pending(),
	));
	let owner = SourceOwner {
		supervisor: Arc::new(Supervisor {
			grant: Arc::clone(&grant),
			digest: scope,
			start,
			retry: Mutex::new(retry),
		}),
		attempt: active.attempt(),
		route: BoundRoute::Direct,
		transport: Arc::clone(&transport),
		retirement_issued: false,
	};
	assert_eq!(owner.observe_read_health(first), Err(RetryError::StaleWork));
	let mut source = VerifiedReads::new(ExactRead { result: Ok(()) }, || {
		owner.observe_read_health(active)
	});
	source.read_exact_at(0, &mut [0]).await.unwrap();
	let delay = owner
		.supervisor
		.observe(|retry, elapsed| Ok(fail_read(retry, elapsed, active) - elapsed))
		.unwrap();
	assert_eq!(delay, Duration::from_millis(500));

	grant.revoke();
	assert_eq!(
		owner.observe_read_health(active),
		Err(RetryError::Blocked(RetryBlock::Permanent(
			PermanentFailure::GrantRevoked
		)))
	);
	transport.stop();
	assert_eq!(owner.observe_read_health(active), Err(route_refusal()));
	assert_eq!(transport.join().await, Ok(()));
}
