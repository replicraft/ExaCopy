//! Bounded checks of the endpoint supervisor's contribution to P-020.

use std::num::{NonZeroU64, NonZeroU128};
use std::time::Duration;

use crate::connection_retry::{
	ConnectionAttempt, ConnectionFailure, FailureDecision, FailureSubject, PermanentFailure,
	ReconnectEvidence, RetryBlock, RetryDecision, RetryError, RetryOwner, RetrySupervisor,
	SourceEpoch, TransientFailure, VerifiedHealth,
};

mod transient_history;

const OWNER: RetryOwner = RetryOwner::new(NonZeroU128::MIN);
const EPOCH: SourceEpoch = SourceEpoch::new(NonZeroU64::MIN);
const TICK: Duration = Duration::from_nanos(1);
const CAUSE: TransientFailure = TransientFailure::NonMutatingTimeout;
const INITIAL_MIN: Duration = Duration::from_millis(500);
const INITIAL_MAX: Duration = Duration::from_secs(1);
const HEALTH_THRESHOLD: Duration = Duration::from_secs(30);

#[kani::proof]
#[kani::unwind(12)]
fn permanent_and_uncertain_failures_never_redial() {
	let expiry = Duration::from_secs(2);
	let mut supervisor = RetrySupervisor::new(OWNER, expiry);
	let attempt = start(&mut supervisor, TICK);
	let online = kani::any::<bool>();
	let subject = if online {
		let binding = supervisor
			.admit(TICK, attempt, fresh_evidence(attempt))
			.expect("fresh admission must succeed");
		FailureSubject::Connection(binding)
	} else {
		FailureSubject::Attempt(attempt)
	};
	let uncertain = kani::any::<bool>();
	let (now, failure, reason) = if uncertain {
		let now = if kani::any() { Duration::ZERO } else { expiry };
		(
			now,
			ConnectionFailure::EffectUncertain,
			RetryBlock::EffectUncertain,
		)
	} else {
		let permanent = permanent_failure();
		(
			TICK,
			ConnectionFailure::Permanent(permanent),
			RetryBlock::Permanent(permanent),
		)
	};

	let decision = supervisor.failure(now, subject, failure);
	kani::assert(
		decision == Ok(FailureDecision::Blocked(reason)),
		"a typed terminal observation immediately blocks the current subject",
	);
	kani::cover!(online && uncertain, "current online ambiguous effect");
	kani::cover!(!online && !uncertain, "definitive refusal during setup");
	assert_remains_blocked(&mut supervisor, reason, expiry);
}

#[kani::proof]
#[kani::solver(minisat)]
#[kani::unwind(12)]
#[kani::stub_verified(crate::connection_retry::equal_jitter)]
fn transient_backoff_is_bounded_and_claims_only_the_due_generation() {
	transient_history::check();
}

#[kani::proof]
#[kani::solver(minisat)]
#[kani::unwind(12)]
fn concrete_transient_backoff_is_bounded_and_claims_only_the_due_generation() {
	transient_history::check();
}

#[kani::proof]
#[kani::unwind(12)]
fn lease_and_revocation_bound_waiting_and_redial() {
	const LEASE_BOUND_MS: u16 = 2_000;
	let lease_ms = kani::any::<u16>();
	kani::assume((1..=LEASE_BOUND_MS).contains(&lease_ms));
	let expiry = Duration::from_millis(u64::from(lease_ms));
	let mut supervisor = RetrySupervisor::new(OWNER, expiry);
	let now = Duration::ZERO;
	let attempt = start(&mut supervisor, now);
	let sample = kani::any::<u32>();
	let wake_at = wait_after(
		&mut supervisor,
		now,
		FailureSubject::Attempt(attempt),
		sample,
	);

	let comparison_owner =
		RetryOwner::new(NonZeroU128::new(2).expect("comparison owner is nonzero"));
	let mut ample_lease = RetrySupervisor::new(comparison_owner, Duration::MAX);
	let comparison = start(&mut ample_lease, now);
	let unclipped = wait_after(
		&mut ample_lease,
		now,
		FailureSubject::Attempt(comparison),
		sample,
	);
	kani::assert(
		(INITIAL_MIN..=INITIAL_MAX).contains(&unclipped),
		"an ample lease leaves the initial jitter window intact",
	);
	kani::assert(
		wake_at == unclipped.min(expiry),
		"the lease clips the jittered wake exactly at expiry",
	);
	kani::assert(
		supervisor.poll(wake_at - TICK) == Ok(RetryDecision::WaitUntil(wake_at)),
		"the wait does not permit early start",
	);
	let revoked = kani::any::<bool>();
	if revoked {
		supervisor.revoke_grant();
		assert_remains_blocked(
			&mut supervisor,
			RetryBlock::Permanent(PermanentFailure::GrantRevoked),
			wake_at,
		);
	} else if wake_at == expiry {
		assert_remains_blocked(&mut supervisor, RetryBlock::GrantExpired, expiry);
	} else {
		let next = start(&mut supervisor, wake_at);
		kani::assert(
			next.generation().get() == 2,
			"a due wake strictly inside the same lease claims the next generation",
		);
		kani::assert(
			supervisor.check_connecting(expiry, next)
				== Err(RetryError::Blocked(RetryBlock::GrantExpired)),
			"the new attempt cannot extend the original lease",
		);
	}
	kani::cover!(
		revoked && wake_at < expiry,
		"revoked during a retryable wait"
	);
	kani::cover!(
		!revoked && unclipped > expiry,
		"wake clipped to lease expiry"
	);
	kani::cover!(!revoked && wake_at < expiry, "redial inside lease");
}

#[kani::proof]
#[kani::unwind(12)]
fn reconnect_requires_current_route_ssh_and_source_and_fences_retired_work() {
	let expiry = Duration::from_secs(3);
	let mut supervisor = RetrySupervisor::new(OWNER, expiry);
	let previous = start(&mut supervisor, Duration::ZERO);
	let old_binding = supervisor
		.admit(Duration::ZERO, previous, fresh_evidence(previous))
		.expect("first fresh admission must succeed");
	let now = wait_after(
		&mut supervisor,
		Duration::ZERO,
		FailureSubject::Connection(old_binding),
		kani::any(),
	);
	let current = start(&mut supervisor, now);
	let foreign_owner = RetryOwner::new(NonZeroU128::new(2).expect("second owner is nonzero"));
	let mut foreign = RetrySupervisor::new(foreign_owner, expiry);
	let foreign_attempt = start(&mut foreign, Duration::ZERO);
	let foreign_now = wait_after(
		&mut foreign,
		Duration::ZERO,
		FailureSubject::Attempt(foreign_attempt),
		0,
	);
	let same_generation = start(&mut foreign, foreign_now);
	kani::assert(
		same_generation.generation() == current.generation(),
		"foreign evidence checks owner identity at the same generation",
	);
	let wrong = if kani::any() {
		previous
	} else {
		same_generation
	};
	let route_current = kani::any::<bool>();
	let ssh_current = kani::any::<bool>();
	let source_current = kani::any::<bool>();
	let evidence = ReconnectEvidence {
		route_checked_for: if route_current { current } else { wrong },
		ssh_authenticated_for: if ssh_current { current } else { wrong },
		source_checked_for: if source_current { current } else { wrong },
		source_epoch: SourceEpoch::new(NonZeroU64::new(2).expect("second epoch is nonzero")),
	};

	kani::assert(
		supervisor.failure(
			expiry,
			FailureSubject::Connection(old_binding),
			ConnectionFailure::EffectUncertain,
		) == Err(RetryError::StaleUncertainEffect),
		"a stale ambiguous report requires separate reconciliation",
	);
	kani::assert(
		supervisor.check_connecting(expiry, wrong) == Err(RetryError::StaleWork),
		"stale work cannot report the clock or retire the current connection attempt",
	);
	kani::assert(
		supervisor.failure(
			expiry,
			FailureSubject::Attempt(previous),
			ConnectionFailure::Transient {
				cause: CAUSE,
				jitter_sample: kani::any(),
			},
		) == Err(RetryError::StaleWork),
		"a stale ordinary failure cannot schedule a wait or report time",
	);
	let all_current = route_current && ssh_current && source_current;
	let binding = if all_current {
		supervisor
			.admit(now, current, evidence)
			.expect("all three observations belong to the current attempt")
	} else {
		kani::assert(
			supervisor.admit(now, current, evidence) == Err(RetryError::StaleAdmission),
			"every independent observation must refer to the current attempt",
		);
		supervisor
			.admit(now, current, fresh_evidence(current))
			.expect("mixed evidence did not consume the current attempt")
	};
	let expected_epoch = if all_current {
		evidence.source_epoch
	} else {
		EPOCH
	};
	kani::assert(
		binding.attempt() == current && binding.source_epoch() == expected_epoch,
		"admission carries the exact fresh attempt and the admitted source epoch",
	);
	kani::assert(
		supervisor.check_completion(expiry, old_binding) == Err(RetryError::StaleWork)
			&& supervisor.check_completion(now, binding).is_ok(),
		"retired completion cannot replace the live binding",
	);
	kani::cover!(all_current, "fresh admission");
	kani::cover!(
		!route_current && ssh_current && source_current,
		"only route stale"
	);
	kani::cover!(
		route_current && !ssh_current && source_current,
		"only SSH stale"
	);
	kani::cover!(
		route_current && ssh_current && !source_current,
		"only source stale"
	);
}

#[kani::proof]
#[kani::unwind(12)]
fn penalty_resets_only_after_current_verified_activity_and_health() {
	const ELAPSED_BOUND_SECONDS: u8 = 60;
	let elapsed_secs = kani::any::<u8>();
	kani::assume(elapsed_secs <= ELAPSED_BOUND_SECONDS);
	let elapsed = if kani::any() {
		HEALTH_THRESHOLD - TICK
	} else {
		Duration::from_secs(u64::from(elapsed_secs))
	};
	let activity = match kani::any::<u8>() % 3 {
		0 => VerifiedHealth::Healthy,
		1 => VerifiedHealth::SuccessfulOperation,
		_ => VerifiedHealth::AuthenticatedHeartbeat,
	};

	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let first = start(&mut supervisor, Duration::ZERO);
	let first_binding = supervisor
		.admit(Duration::ZERO, first, fresh_evidence(first))
		.expect("the first attempt admits a checked source");
	let due = wait_after(
		&mut supervisor,
		Duration::ZERO,
		FailureSubject::Connection(first_binding),
		kani::any(),
	);
	let current = start(&mut supervisor, due);
	let binding = supervisor
		.admit(due, current, fresh_evidence(current))
		.expect("current attempt admits a checked source");
	kani::assert(
		supervisor.observe_health(
			due + HEALTH_THRESHOLD,
			first_binding,
			VerifiedHealth::SuccessfulOperation,
		) == Err(RetryError::StaleWork),
		"retired activity cannot qualify the new connection or report time",
	);
	supervisor
		.observe_health(due, binding, activity)
		.expect("the activity is bound to the admitted attempt");
	let now = due + elapsed;
	supervisor
		.observe_health(now, binding, VerifiedHealth::Healthy)
		.expect("the current health observation is admitted");
	let wake = wait_after(
		&mut supervisor,
		now,
		FailureSubject::Connection(binding),
		u32::MAX,
	);
	let reset = elapsed >= HEALTH_THRESHOLD && activity != VerifiedHealth::Healthy;
	let expected = if reset { INITIAL_MAX } else { INITIAL_MAX * 2 };
	kani::assert(
		wake == now + expected,
		"reset requires both qualifying activity and the full healthy duration",
	);
	kani::cover!(
		reset && elapsed == HEALTH_THRESHOLD,
		"reset at the exact threshold"
	);
	kani::cover!(
		!reset && elapsed >= HEALTH_THRESHOLD,
		"healthy without successful activity"
	);
	kani::cover!(
		elapsed == HEALTH_THRESHOLD - TICK && activity == VerifiedHealth::SuccessfulOperation,
		"successful activity one tick before the health threshold"
	);
}

#[kani::proof]
#[kani::unwind(12)]
fn clock_rollback_and_unrepresentable_wake_are_terminal() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let rollback = kani::any::<bool>();
	let now = if rollback { TICK } else { Duration::MAX - TICK };
	let attempt = start(&mut supervisor, now);
	let failure = ConnectionFailure::Transient {
		cause: CAUSE,
		jitter_sample: kani::any(),
	};
	let subject = FailureSubject::Attempt(attempt);
	let reason = if rollback {
		kani::assert(
			supervisor.failure(Duration::ZERO, subject, failure)
				== Err(RetryError::Blocked(RetryBlock::ClockRollback)),
			"a clock rollback cannot schedule a new attempt",
		);
		RetryBlock::ClockRollback
	} else {
		kani::assert(
			supervisor.failure(now, subject, failure)
				== Ok(FailureDecision::Blocked(RetryBlock::ClockRangeExhausted)),
			"deadline overflow does not wrap into a retry",
		);
		RetryBlock::ClockRangeExhausted
	};
	assert_remains_blocked(&mut supervisor, reason, now);
	kani::cover!(rollback, "rollback branch");
	kani::cover!(!rollback, "wake overflow branch");
}

fn start(supervisor: &mut RetrySupervisor, now: Duration) -> ConnectionAttempt {
	let Ok(RetryDecision::Start(attempt)) = supervisor.poll(now) else {
		panic!("a fresh attempt must start at the authorized time {now:?}");
	};
	attempt
}

fn wait_after(
	supervisor: &mut RetrySupervisor,
	now: Duration,
	subject: FailureSubject,
	jitter_sample: u32,
) -> Duration {
	let failure = ConnectionFailure::Transient {
		cause: CAUSE,
		jitter_sample,
	};
	let Ok(FailureDecision::WaitUntil {
		wake_at,
		cause: CAUSE,
	}) = supervisor.failure(now, subject, failure)
	else {
		panic!("a current transient loss under a live lease must schedule a wait");
	};
	wake_at
}

fn assert_remains_blocked(supervisor: &mut RetrySupervisor, reason: RetryBlock, now: Duration) {
	let expected = Err(RetryError::Blocked(reason));
	kani::assert(
		supervisor.poll(now) == expected,
		"terminal reason stops redial",
	);
	supervisor.revoke_grant();
	kani::assert(
		supervisor.poll(Duration::MAX) == expected,
		"lease expiry and revocation preserve the original terminal reason",
	);
	kani::assert(
		supervisor.poll(Duration::ZERO) == expected,
		"a later rollback preserves the original terminal reason",
	);
}

fn fresh_evidence(attempt: ConnectionAttempt) -> ReconnectEvidence {
	ReconnectEvidence {
		route_checked_for: attempt,
		ssh_authenticated_for: attempt,
		source_checked_for: attempt,
		source_epoch: EPOCH,
	}
}

fn permanent_failure() -> PermanentFailure {
	use PermanentFailure::{
		CredentialRejected, CredentialUnavailable, GrantRevoked, HostIdentityRefused,
		IntegrityFailure, InvalidConfiguration, PermissionDenied, ResourceBlocked,
		RouteAuthorityRefused, SourceChanged, UnsupportedCapability,
	};

	const PERMANENT_CAUSES: [PermanentFailure; 11] = [
		CredentialRejected,
		CredentialUnavailable,
		GrantRevoked,
		HostIdentityRefused,
		IntegrityFailure,
		InvalidConfiguration,
		PermissionDenied,
		ResourceBlocked,
		RouteAuthorityRefused,
		SourceChanged,
		UnsupportedCapability,
	];
	let index = usize::from(kani::any::<u8>());
	kani::assume(index < PERMANENT_CAUSES.len());
	PERMANENT_CAUSES[index]
}
