//! Exercise retry decisions with an injected clock, jitter and connection evidence.

use std::num::{NonZeroU64, NonZeroU128};
use std::time::Duration;

use exacopy_endpoint::connection_retry::{
	ConnectionAttempt, ConnectionBinding, ConnectionFailure, FailureDecision, FailureSubject,
	PermanentFailure, ReconnectEvidence, RetryBlock, RetryDecision, RetryError, RetryOwner,
	RetrySupervisor, SourceEpoch, TransientFailure, VerifiedHealth,
};

const OWNER: RetryOwner = RetryOwner::new(NonZeroU128::MIN);
const EPOCH: SourceEpoch = SourceEpoch::new(NonZeroU64::MIN);
const CAUSE: TransientFailure = TransientFailure::TransportInterrupted;

fn start(supervisor: &mut RetrySupervisor, now: Duration) -> ConnectionAttempt {
	match supervisor.poll(now) {
		Ok(RetryDecision::Start(attempt)) => attempt,
		result => panic!("expected one attempt at {now:?}, got {result:?}"),
	}
}

fn checked_evidence(attempt: ConnectionAttempt) -> ReconnectEvidence {
	ReconnectEvidence {
		route_checked_for: attempt,
		ssh_authenticated_for: attempt,
		source_checked_for: attempt,
		source_epoch: EPOCH,
	}
}

fn admit(
	supervisor: &mut RetrySupervisor,
	now: Duration,
	attempt: ConnectionAttempt,
) -> ConnectionBinding {
	supervisor
		.admit(now, attempt, checked_evidence(attempt))
		.expect("matching fresh admission should succeed")
}

fn disconnect(
	supervisor: &mut RetrySupervisor,
	now: Duration,
	subject: FailureSubject,
	sample: u32,
) -> Duration {
	let loss = ConnectionFailure::Transient {
		cause: CAUSE,
		jitter_sample: sample,
	};
	match supervisor.failure(now, subject, loss) {
		Ok(FailureDecision::WaitUntil {
			wake_at,
			cause: CAUSE,
		}) => wake_at,
		result => panic!("expected retry for current transient work at {now:?}, got {result:?}"),
	}
}

#[test]
fn literal_jitter_windows_double_and_cap_without_overlapping_attempts() {
	const LOW_MS: [u64; 8] = [500, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000];
	const MID_MS: [u64; 8] = [750, 1_500, 3_000, 6_000, 12_000, 24_000, 45_000, 45_000];
	const HIGH_MS: [u64; 8] = [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000];
	for (sample, windows) in [(0, LOW_MS), (1 << 31, MID_MS), (u32::MAX, HIGH_MS)] {
		let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
		let mut now = Duration::ZERO;
		for (index, expected_ms) in windows.into_iter().enumerate() {
			let attempt = start(&mut supervisor, now);
			assert_eq!(
				attempt.generation().get(),
				u64::try_from(index + 1).expect("small index")
			);
			assert_eq!(supervisor.poll(now), Err(RetryError::Busy));
			let due = disconnect(
				&mut supervisor,
				now,
				FailureSubject::Attempt(attempt),
				sample,
			);
			assert_eq!(due - now, Duration::from_millis(expected_ms));
			assert_eq!(
				supervisor.poll(due - Duration::from_nanos(1)),
				Ok(RetryDecision::WaitUntil(due))
			);
			now = due;
		}
	}
}

#[test]
fn five_days_of_outage_keep_scheduling_safe_retries() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let mut now = Duration::ZERO;
	let end = Duration::from_hours(5 * 24);
	let mut attempted = 0;
	while now < end {
		let attempt = start(&mut supervisor, now);
		attempted += 1;
		assert_eq!(attempt.generation().get(), attempted);
		let due = disconnect(&mut supervisor, now, FailureSubject::Attempt(attempt), 0);
		assert!(due > now && due - now <= Duration::from_mins(1));
		now = due;
	}
	assert!(
		attempted > 14_000,
		"long outage reached only {attempted} attempts"
	);
}

#[test]
fn reset_requires_success_and_thirty_healthy_seconds_on_the_same_connection() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let first = start(&mut supervisor, Duration::ZERO);
	let due = disconnect(
		&mut supervisor,
		Duration::ZERO,
		FailureSubject::Attempt(first),
		u32::MAX,
	);
	let attempt = start(&mut supervisor, due);
	let binding = admit(&mut supervisor, due, attempt);
	let now = due + Duration::from_secs(29);
	supervisor
		.observe_health(now, binding, VerifiedHealth::SuccessfulOperation)
		.expect("current success");
	let due = disconnect(
		&mut supervisor,
		now,
		FailureSubject::Connection(binding),
		u32::MAX,
	);
	assert_eq!(
		due - now,
		Duration::from_secs(2),
		"early success keeps backoff"
	);

	let attempt = start(&mut supervisor, due);
	let binding = admit(&mut supervisor, due, attempt);
	let now = due + Duration::from_secs(30);
	supervisor
		.observe_health(now, binding, VerifiedHealth::Healthy)
		.expect("current health");
	let due = disconnect(
		&mut supervisor,
		now,
		FailureSubject::Connection(binding),
		u32::MAX,
	);
	assert_eq!(
		due - now,
		Duration::from_secs(4),
		"health without success keeps backoff"
	);

	let attempt = start(&mut supervisor, due);
	let binding = admit(&mut supervisor, due, attempt);
	supervisor
		.observe_health(due, binding, VerifiedHealth::AuthenticatedHeartbeat)
		.expect("current heartbeat");
	let now = due + Duration::from_secs(30);
	supervisor
		.observe_health(now, binding, VerifiedHealth::Healthy)
		.expect("current health");
	let due = disconnect(
		&mut supervisor,
		now,
		FailureSubject::Connection(binding),
		u32::MAX,
	);
	assert_eq!(
		due - now,
		Duration::from_secs(1),
		"verified healthy connection resets backoff"
	);
}

#[test]
fn reconnect_requires_each_fresh_admission_and_fences_old_completions() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let first = start(&mut supervisor, Duration::ZERO);
	let old = admit(&mut supervisor, Duration::ZERO, first);
	let now = disconnect(
		&mut supervisor,
		Duration::ZERO,
		FailureSubject::Connection(old),
		0,
	);
	assert_eq!(
		supervisor.check_completion(Duration::ZERO, old),
		Err(RetryError::StaleWork)
	);
	let second = start(&mut supervisor, now);
	let current = checked_evidence(second);
	for stale in [
		ReconnectEvidence {
			route_checked_for: first,
			..current
		},
		ReconnectEvidence {
			ssh_authenticated_for: first,
			..current
		},
		ReconnectEvidence {
			source_checked_for: first,
			..current
		},
	] {
		assert_eq!(
			supervisor.admit(now, second, stale),
			Err(RetryError::StaleAdmission)
		);
	}
	assert_eq!(
		supervisor.admit(Duration::ZERO, first, checked_evidence(first)),
		Err(RetryError::StaleWork)
	);
	let updated_epoch = SourceEpoch::new(NonZeroU64::new(2).expect("second source epoch"));
	let current = ReconnectEvidence {
		source_epoch: updated_epoch,
		..current
	};
	let new = supervisor
		.admit(now, second, current)
		.expect("each current check was supplied");
	assert_eq!(new.source_epoch(), updated_epoch);
	assert_eq!(new.attempt(), second);
	assert_eq!(
		supervisor.check_completion(Duration::ZERO, old),
		Err(RetryError::StaleWork)
	);
	assert_eq!(
		supervisor.observe_health(Duration::ZERO, old, VerifiedHealth::SuccessfulOperation),
		Err(RetryError::StaleWork)
	);
	assert_eq!(
		supervisor.failure(
			Duration::ZERO,
			FailureSubject::Attempt(second),
			ConnectionFailure::Permanent(PermanentFailure::CredentialRejected)
		),
		Err(RetryError::StaleWork)
	);
	assert_eq!(supervisor.check_completion(now, new), Ok(()));
}

#[test]
fn matching_generations_from_distinct_supervisors_cannot_cross() {
	let mut first = RetrySupervisor::new(OWNER, Duration::MAX);
	let mut second = RetrySupervisor::new(
		RetryOwner::new(NonZeroU128::new(2).expect("other owner")),
		Duration::MAX,
	);
	let a = start(&mut first, Duration::ZERO);
	let b = start(&mut second, Duration::ZERO);
	assert_eq!(a.generation(), b.generation());
	assert_eq!(
		first.admit(Duration::ZERO, a, checked_evidence(b)),
		Err(RetryError::StaleAdmission)
	);
	let binding = admit(&mut second, Duration::ZERO, b);
	let _current = admit(&mut first, Duration::ZERO, a);
	assert_eq!(
		first.check_completion(Duration::ZERO, binding),
		Err(RetryError::StaleWork)
	);
}

#[test]
fn security_integrity_and_resource_refusals_never_become_timed_retries() {
	use PermanentFailure::{
		CredentialRejected, CredentialUnavailable, GrantRevoked, HostIdentityRefused,
		IntegrityFailure, InvalidConfiguration, PermissionDenied, ResourceBlocked,
		RouteAuthorityRefused, SourceChanged, UnsupportedCapability,
	};
	for cause in [
		CredentialRejected,
		CredentialUnavailable,
		HostIdentityRefused,
		RouteAuthorityRefused,
		GrantRevoked,
		UnsupportedCapability,
		InvalidConfiguration,
		PermissionDenied,
		ResourceBlocked,
		SourceChanged,
		IntegrityFailure,
	] {
		let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
		let attempt = start(&mut supervisor, Duration::ZERO);
		let reason = RetryBlock::Permanent(cause);
		assert_eq!(
			supervisor.failure(
				Duration::ZERO,
				FailureSubject::Attempt(attempt),
				ConnectionFailure::Permanent(cause)
			),
			Ok(FailureDecision::Blocked(reason))
		);
		assert_eq!(
			supervisor.poll(Duration::from_hours(12)),
			Err(RetryError::Blocked(reason))
		);
	}
}

#[test]
fn ambiguous_effects_stop_current_work_and_are_reported_when_stale() {
	let expiry = Duration::from_secs(1);
	let mut supervisor = RetrySupervisor::new(OWNER, expiry);
	let attempt = start(&mut supervisor, Duration::ZERO);
	let binding = admit(&mut supervisor, Duration::ZERO, attempt);
	let subject = FailureSubject::Connection(binding);
	let uncertain = ConnectionFailure::EffectUncertain;
	assert_eq!(
		supervisor.failure(expiry, subject, uncertain),
		Ok(FailureDecision::Blocked(RetryBlock::EffectUncertain))
	);
	assert_eq!(
		supervisor.poll(expiry),
		Err(RetryError::Blocked(RetryBlock::EffectUncertain))
	);

	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let attempt = start(&mut supervisor, Duration::ZERO);
	let subject = FailureSubject::Connection(admit(&mut supervisor, Duration::ZERO, attempt));
	let now = disconnect(&mut supervisor, Duration::ZERO, subject, 0);
	let next = start(&mut supervisor, now);
	assert_eq!(
		supervisor.failure(Duration::ZERO, subject, uncertain),
		Err(RetryError::StaleUncertainEffect)
	);
	assert_eq!(
		supervisor
			.admit(now, next, checked_evidence(next))
			.map(ConnectionBinding::attempt),
		Ok(next)
	);
}

#[test]
fn expiry_is_exclusive_while_waiting_connecting_or_online() {
	let deadline = Duration::from_millis(500);
	let mut supervisor = RetrySupervisor::new(OWNER, deadline);
	let attempt = start(&mut supervisor, Duration::ZERO);
	assert_eq!(
		disconnect(
			&mut supervisor,
			Duration::ZERO,
			FailureSubject::Attempt(attempt),
			u32::MAX
		),
		deadline
	);
	let expired = RetryError::Blocked(RetryBlock::GrantExpired);
	assert_eq!(
		supervisor.poll(deadline - Duration::from_nanos(1)),
		Ok(RetryDecision::WaitUntil(deadline))
	);
	assert_eq!(supervisor.poll(deadline), Err(expired));
	assert_eq!(
		supervisor.poll(Duration::ZERO),
		Err(expired),
		"a later rollback cannot reopen the grant"
	);

	let mut supervisor = RetrySupervisor::new(OWNER, deadline);
	let attempt = start(&mut supervisor, Duration::ZERO);
	assert_eq!(
		supervisor.admit(deadline, attempt, checked_evidence(attempt)),
		Err(expired)
	);

	let mut supervisor = RetrySupervisor::new(OWNER, deadline);
	let attempt = start(&mut supervisor, Duration::ZERO);
	let binding = admit(&mut supervisor, Duration::ZERO, attempt);
	assert_eq!(
		supervisor.check_completion(deadline - Duration::from_nanos(1), binding),
		Ok(())
	);
	assert_eq!(supervisor.check_completion(deadline, binding), Err(expired));
}

#[test]
fn clock_rollback_and_deadline_overflow_fail_closed() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let later = Duration::from_secs(10);
	let attempt = start(&mut supervisor, later);
	let until = disconnect(&mut supervisor, later, FailureSubject::Attempt(attempt), 0);
	let rollback = RetryError::Blocked(RetryBlock::ClockRollback);
	assert_eq!(
		supervisor.poll(later - Duration::from_nanos(1)),
		Err(rollback)
	);
	assert_eq!(supervisor.poll(until), Err(rollback));

	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let near_limit = Duration::MAX - Duration::from_millis(1);
	let attempt = start(&mut supervisor, near_limit);
	let failure = ConnectionFailure::Transient {
		cause: CAUSE,
		jitter_sample: 0,
	};
	assert_eq!(
		supervisor.failure(near_limit, FailureSubject::Attempt(attempt), failure),
		Ok(FailureDecision::Blocked(RetryBlock::ClockRangeExhausted))
	);
	assert_eq!(
		supervisor.poll(Duration::MAX),
		Err(RetryError::Blocked(RetryBlock::ClockRangeExhausted))
	);
}

#[test]
fn revoking_authority_while_waiting_prevents_another_dial() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let attempt = start(&mut supervisor, Duration::ZERO);
	let wake = disconnect(
		&mut supervisor,
		Duration::ZERO,
		FailureSubject::Attempt(attempt),
		0,
	);
	supervisor.revoke_grant();
	assert_eq!(
		supervisor.poll(wake),
		Err(RetryError::Blocked(RetryBlock::Permanent(
			PermanentFailure::GrantRevoked
		))),
	);

	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let attempt = start(&mut supervisor, Duration::ZERO);
	let stopped = supervisor.failure(
		Duration::ZERO,
		FailureSubject::Attempt(attempt),
		ConnectionFailure::EffectUncertain,
	);
	assert_eq!(
		stopped,
		Ok(FailureDecision::Blocked(RetryBlock::EffectUncertain))
	);
	supervisor.revoke_grant();
	assert_eq!(
		supervisor.poll(wake),
		Err(RetryError::Blocked(RetryBlock::EffectUncertain))
	);
}
