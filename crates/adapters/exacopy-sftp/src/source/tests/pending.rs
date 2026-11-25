use exacopy_endpoint::connection_retry::{
	ConnectionAttempt, ConnectionFailure, FailureDecision, FailureSubject, PermanentFailure,
	RetryBlock, RetryError, TransientFailure,
};

use super::{
	CapturedReadAt, ConnectionBinding, Duration, EPOCH, Generated, NonZeroU64, NonZeroU128,
};
use super::{Ordering, ReconnectEvidence, RetryDecision, RetryOwner, RetrySupervisor, SourceEpoch};
use super::{SftpSourceError, path, peer_source};
use crate::{PendingSftpSourceRequest, PendingSourceOwner, with_pending_source};

const EXPIRY: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
enum Interruption {
	Expire,
	Revoke,
}

struct Owner {
	supervisor: RetrySupervisor,
	now: Duration,
	connecting_checks: u8,
	after_open: Option<Interruption>,
}

impl Owner {
	fn start(id: NonZeroU128) -> (Self, ConnectionAttempt) {
		let mut supervisor = RetrySupervisor::new(RetryOwner::new(id), EXPIRY);
		let RetryDecision::Start(attempt) = supervisor.poll(Duration::ZERO).unwrap() else {
			panic!("fixture must start exactly one attempt");
		};
		(
			Self {
				supervisor,
				now: Duration::ZERO,
				connecting_checks: 0,
				after_open: None,
			},
			attempt,
		)
	}

	fn admit(
		&mut self,
		attempt: ConnectionAttempt,
		source_epoch: SourceEpoch,
	) -> ConnectionBinding {
		self.supervisor
			.admit(
				self.now,
				attempt,
				ReconnectEvidence {
					route_checked_for: attempt,
					ssh_authenticated_for: attempt,
					source_checked_for: attempt,
					source_epoch,
				},
			)
			.unwrap()
	}

	fn check_binding(&mut self, binding: ConnectionBinding) -> Result<(), RetryError> {
		self.supervisor.check_completion(self.now, binding)
	}
}

impl PendingSourceOwner for Owner {
	fn check_connecting(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.connecting_checks += 1;
		if self.connecting_checks == 2 {
			match self.after_open {
				Some(Interruption::Expire) => self.now = EXPIRY,
				Some(Interruption::Revoke) => self.supervisor.revoke_grant(),
				None => {}
			}
		}
		self.supervisor.check_connecting(self.now, attempt)
	}

	fn check_attempt(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.supervisor.check_attempt(self.now, attempt)
	}
}

#[tokio::test]
async fn pending_metadata_activates_exactly_the_same_held_handle() {
	let (session, calls) = peer_source(Generated::new(3)).await;
	let (mut owner, attempt) = Owner::start(NonZeroU128::MIN);
	let result = with_pending_source(
		session,
		PendingSftpSourceRequest {
			path: &path(),
			attempt,
			epoch: EPOCH,
		},
		&mut owner,
		async |pending, owner| {
			assert_eq!(pending.attempt(), attempt);
			assert_eq!(pending.epoch(), EPOCH);
			let observation = pending.observation();
			assert_eq!(
				(observation.length, observation.mode, observation.modified),
				(3, 0o100600, 22)
			);
			assert_eq!(calls.open.load(Ordering::Relaxed), 1);
			assert_eq!(calls.read.load(Ordering::Relaxed), 0);
			let binding = owner.admit(pending.attempt(), pending.epoch());
			let mut source = pending.activate(binding, |binding| owner.check_binding(binding))?;
			let mut bytes = [0; 3];
			source.read_exact_at(0, &mut bytes).await?;
			source.finish().await?;
			Ok::<_, SftpSourceError>(bytes)
		},
	)
	.await
	.unwrap()
	.unwrap();
	assert_eq!(result, [0, 1, 2]);
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn expired_or_retired_attempt_does_not_open_a_remote_handle() {
	for expected in [
		RetryError::StaleWork,
		RetryError::Blocked(RetryBlock::GrantExpired),
	] {
		let (session, calls) = peer_source(Generated::new(3)).await;
		let (mut owner, attempt) = Owner::start(NonZeroU128::MIN);
		if expected == RetryError::StaleWork {
			let decision = owner
				.supervisor
				.failure(
					Duration::ZERO,
					FailureSubject::Attempt(attempt),
					ConnectionFailure::Transient {
						cause: TransientFailure::TransportInterrupted,
						jitter_sample: 0,
					},
				)
				.unwrap();
			assert!(matches!(decision, FailureDecision::WaitUntil { .. }));
		} else {
			owner.now = EXPIRY;
		}
		let result = with_pending_source(
			session,
			PendingSftpSourceRequest {
				path: &path(),
				attempt,
				epoch: EPOCH,
			},
			&mut owner,
			async |_, _| -> Result<(), ()> { panic!("refused open has no admission callback") },
		)
		.await;
		assert!(matches!(result, Err(SftpSourceError::Binding(cause)) if cause == expected));
		assert_eq!(calls.open.load(Ordering::Relaxed), 0);
		assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	}
}

#[tokio::test]
async fn revoked_or_expired_after_pending_open_refuses_before_callback() {
	for (interruption, expected) in [
		(Interruption::Expire, RetryBlock::GrantExpired),
		(
			Interruption::Revoke,
			RetryBlock::Permanent(PermanentFailure::GrantRevoked),
		),
	] {
		let (session, calls) = peer_source(Generated::new(3)).await;
		let (mut owner, attempt) = Owner::start(NonZeroU128::MIN);
		owner.after_open = Some(interruption);
		let result = with_pending_source(
			session,
			PendingSftpSourceRequest {
				path: &path(),
				attempt,
				epoch: EPOCH,
			},
			&mut owner,
			async |_, _| -> Result<(), ()> { panic!("retired source cannot reach the callback") },
		)
		.await;
		assert!(
			matches!(result, Err(SftpSourceError::Binding(RetryError::Blocked(cause))) if cause == expected)
		);
		assert_eq!(calls.open.load(Ordering::Relaxed), 1);
		assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	}
}

#[tokio::test]
async fn wrong_attempt_or_epoch_cannot_activate_pending_source() {
	for wrong_attempt in [true, false] {
		let (session, calls) = peer_source(Generated::new(3)).await;
		let (mut owner, attempt) = Owner::start(NonZeroU128::MIN);
		let result = with_pending_source(
			session,
			PendingSftpSourceRequest {
				path: &path(),
				attempt,
				epoch: EPOCH,
			},
			&mut owner,
			async |pending, owner| {
				let binding = if wrong_attempt {
					let (mut foreign, wrong) = Owner::start(NonZeroU128::new(2).unwrap());
					foreign.admit(wrong, EPOCH)
				} else {
					owner.admit(attempt, SourceEpoch::new(NonZeroU64::new(2).unwrap()))
				};
				pending.activate(binding, |_| {
					panic!("wrong binding cannot reach current check")
				})?;
				Ok::<_, SftpSourceError>(())
			},
		)
		.await
		.unwrap();
		if wrong_attempt {
			assert!(matches!(
				result,
				Err(SftpSourceError::Binding(RetryError::StaleWork))
			));
		} else {
			assert!(matches!(result, Err(SftpSourceError::Epoch)));
		}
		assert_eq!(calls.open.load(Ordering::Relaxed), 1);
		assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	}
}

#[tokio::test]
async fn a_matching_binding_still_needs_current_activation_authority() {
	let (session, calls) = peer_source(Generated::new(3)).await;
	let (mut owner, attempt) = Owner::start(NonZeroU128::MIN);
	let result = with_pending_source(
		session,
		PendingSftpSourceRequest {
			path: &path(),
			attempt,
			epoch: EPOCH,
		},
		&mut owner,
		async |pending, owner| {
			let binding = owner.admit(pending.attempt(), pending.epoch());
			owner.supervisor.revoke_grant();
			pending.activate(binding, |binding| owner.check_binding(binding))?;
			Ok::<_, SftpSourceError>(())
		},
	)
	.await
	.unwrap();
	assert!(matches!(
		result,
		Err(SftpSourceError::Binding(RetryError::Blocked(
			RetryBlock::Permanent(PermanentFailure::GrantRevoked),
		)))
	));
	assert_eq!(calls.open.load(Ordering::Relaxed), 1);
	assert_eq!(calls.read.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn callback_refusal_preserves_durable_error_and_discards_stale_success() {
	const UNCERTAIN: &str = "private journal barrier uncertain";
	for uncertain in [true, false] {
		let (session, calls) = peer_source(Generated::new(3)).await;
		let (mut owner, attempt) = Owner::start(NonZeroU128::MIN);
		let result = with_pending_source(
			session,
			PendingSftpSourceRequest {
				path: &path(),
				attempt,
				epoch: EPOCH,
			},
			&mut owner,
			async |pending, owner| {
				let binding = owner.admit(pending.attempt(), pending.epoch());
				let source = pending
					.activate(binding, |binding| owner.check_binding(binding))
					.unwrap();
				drop(source);
				owner.supervisor.revoke_grant();
				if uncertain { Err(UNCERTAIN) } else { Ok(()) }
			},
		)
		.await;
		if uncertain {
			assert_eq!(result.unwrap(), Err(UNCERTAIN));
		} else {
			assert!(matches!(
				result,
				Err(SftpSourceError::Binding(RetryError::Blocked(
					RetryBlock::Permanent(PermanentFailure::GrantRevoked),
				)))
			));
		}
		assert_eq!(calls.read.load(Ordering::Relaxed), 0);
	}
}
