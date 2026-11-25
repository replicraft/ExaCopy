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
