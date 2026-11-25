use std::num::NonZeroU128;
use std::time::Duration;

use super::{RetryBlock, RetryError, RetryOwner, RetrySupervisor};

#[test]
fn generation_exhaustion_permanently_refuses_identity_reuse() {
	let mut supervisor = RetrySupervisor::new(RetryOwner::new(NonZeroU128::MIN), Duration::MAX);
	supervisor.generation = u64::MAX;
	let blocked = Err(RetryError::Blocked(RetryBlock::GenerationExhausted));
	assert_eq!(supervisor.poll(Duration::ZERO), blocked);
	assert_eq!(supervisor.poll(Duration::from_secs(1)), blocked);
}

#[test]
fn pending_checks_are_exact_and_do_not_extend_the_grant() {
	use std::num::NonZeroU64;

	use super::{ReconnectEvidence, RetryDecision, SourceEpoch};

	let expiration = Duration::from_secs(2);
	let mut owner = RetrySupervisor::new(RetryOwner::new(NonZeroU128::MIN), expiration);
	let mut foreign =
		RetrySupervisor::new(RetryOwner::new(NonZeroU128::new(2).unwrap()), expiration);
	let RetryDecision::Start(attempt) = owner.poll(Duration::ZERO).unwrap() else {
		panic!("first attempt must start");
	};
	let RetryDecision::Start(other) = foreign.poll(Duration::ZERO).unwrap() else {
		panic!("foreign attempt must start");
	};

	assert_eq!(
		owner.check_connecting(expiration, other),
		Err(RetryError::StaleWork)
	);
	assert_eq!(
		owner.check_attempt(expiration, other),
		Err(RetryError::StaleWork)
	);
	assert_eq!(owner.check_connecting(Duration::ZERO, attempt), Ok(()));
	owner
		.admit(
			Duration::ZERO,
			attempt,
			ReconnectEvidence {
				route_checked_for: attempt,
				ssh_authenticated_for: attempt,
				source_checked_for: attempt,
				source_epoch: SourceEpoch::new(NonZeroU64::MIN),
			},
		)
		.unwrap();
	assert_eq!(
		owner.check_connecting(Duration::ZERO, attempt),
		Err(RetryError::StaleWork)
	);
	assert_eq!(owner.check_attempt(Duration::ZERO, attempt), Ok(()));
	assert_eq!(
		owner.check_attempt(expiration, attempt),
		Err(RetryError::Blocked(RetryBlock::GrantExpired)),
	);
}
