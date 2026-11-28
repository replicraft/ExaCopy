//! Pure scheduling and generation fencing for a single remote connection supervisor.
//!
//! The coordinator owns the fixed job authority, route and SSH policy, source
//! revalidation, request identity and reconciliation. Each adapter observation
//! must be truthful and associated with the actual attempt that produced it.
//! All clock readings use the same injected monotonic epoch. This module holds
//! no credentials and performs no dial, clock, random, filesystem or task I/O.

use std::num::NonZeroU64;
use std::time::Duration;

mod decision;

#[cfg(test)]
mod tests;

pub use crate::remote_source::SourceEpoch;

pub use decision::{
	ConnectionFailure, FailureDecision, FailureSubject, PermanentFailure, RetryBlock,
	RetryDecision, RetryError, RetryOwner, TransientFailure, VerifiedHealth,
};

const INITIAL_BACKOFF_MS: u64 = 1_000;
const MAX_BACKOFF_MS: u64 = 60_000;
const HEALTHY_RESET_AFTER: Duration = Duration::from_secs(30);

/// Identifies one connection attempt within a uniquely reserved supervisor lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionAttempt {
	owner: RetryOwner,
	generation: NonZeroU64,
}

impl ConnectionAttempt {
	/// The strictly increasing generation allocated by this supervisor.
	#[must_use]
	pub const fn generation(self) -> NonZeroU64 {
		self.generation
	}
}

/// Separate fresh observations from route, SSH and source admission.
///
/// Obtain each fact under the reported attempt. A previously approved route or
/// source epoch may be revalidated, but evidence observed under an older attempt
/// cannot be used directly. Route confinement, trust, and source equality are
/// established by the owning adapters and coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectEvidence {
	/// Attempt under which current approved route evidence was checked.
	pub route_checked_for: ConnectionAttempt,
	/// Attempt under which the same approved SSH authority was authenticated.
	pub ssh_authenticated_for: ConnectionAttempt,
	/// Attempt under which the current authorized source view was checked.
	pub source_checked_for: ConnectionAttempt,
	/// The coordinator's source generation after revalidation.
	pub source_epoch: SourceEpoch,
}

/// Successful connection admission bound to its attempt and source epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionBinding {
	attempt: ConnectionAttempt,
	source_epoch: SourceEpoch,
}

impl ConnectionBinding {
	/// Returns the admitted attempt for downstream request labeling.
	#[must_use]
	pub const fn attempt(self) -> ConnectionAttempt {
		self.attempt
	}

	/// Returns the admitted source generation for downstream request labeling.
	#[must_use]
	pub const fn source_epoch(self) -> SourceEpoch {
		self.source_epoch
	}
}

#[derive(Debug, Clone, Copy)]
enum Phase {
	Ready,
	Waiting(Duration),
	Connecting(ConnectionAttempt),
	Online(ConnectionBinding, Health),
	Blocked(RetryBlock),
}

#[derive(Debug, Clone, Copy)]
struct Health {
	since: Duration,
	succeeded: bool,
}

/// Schedules at most one attempt and stores fixed-size state for any outage length.
#[derive(Debug)]
pub struct RetrySupervisor {
	owner: RetryOwner,
	grant_expires_at: Duration,
	last_observation: Duration,
	generation: u64,
	next_backoff_ms: u64,
	phase: Phase,
}

impl RetrySupervisor {
	/// Creates a ready supervisor for a fixed authorization lease.
	///
	/// The caller derives the exclusive monotonic expiry conservatively from the
	/// authenticated grant. The authority owner must report revocation and
	/// enforce wall-clock validity at its boundary. Renewed authority requires a fresh
	/// supervisor owner and a new explicit admission.
	#[must_use]
	pub const fn new(owner: RetryOwner, grant_expires_at: Duration) -> Self {
		Self {
			owner,
			grant_expires_at,
			last_observation: Duration::ZERO,
			generation: 0,
			next_backoff_ms: INITIAL_BACKOFF_MS,
			phase: Phase::Ready,
		}
	}

	/// Blocks this supervisor when its owning authority revokes the grant.
	/// A terminal outcome already observed, including an uncertain effect, is retained.
	pub fn revoke_grant(&mut self) {
		if !matches!(self.phase, Phase::Blocked(_)) {
			self.phase = Phase::Blocked(RetryBlock::Permanent(PermanentFailure::GrantRevoked));
		}
	}

	/// Polls for one fresh attempt and claims its generation when due.
	///
	/// # Errors
	/// Refuses overlapping attempts and connections. Expired authority, clock
	/// rollback and exhausted identity space permanently stop scheduling.
	pub fn poll(&mut self, now: Duration) -> Result<RetryDecision, RetryError> {
		self.observe_time(now)?;
		match self.phase {
			Phase::Waiting(wake_at) if now < wake_at => {
				return Ok(RetryDecision::WaitUntil(wake_at));
			}
			Phase::Connecting(_) | Phase::Online(..) => return Err(RetryError::Busy),
			Phase::Blocked(reason) => return Err(RetryError::Blocked(reason)),
			Phase::Ready | Phase::Waiting(_) => {}
		}
		let Some(generation) = self.generation.checked_add(1).and_then(NonZeroU64::new) else {
			return Err(self.block(RetryBlock::GenerationExhausted));
		};
		self.generation = generation.get();
		let attempt = ConnectionAttempt {
			owner: self.owner,
			generation,
		};
		self.phase = Phase::Connecting(attempt);
		Ok(RetryDecision::Start(attempt))
	}

	/// Checks the current authorized attempt while its source is still pending.
	/// # Errors
	/// Refuses a foreign, retired or already admitted attempt, expired authority,
	/// and invalid time. Does not establish route, SSH or source evidence.
	pub fn check_connecting(
		&mut self,
		now: Duration,
		attempt: ConnectionAttempt,
	) -> Result<(), RetryError> {
		self.check_subject(FailureSubject::Attempt(attempt))?;
		self.observe_time(now)
	}

	/// Checks the exact live attempt before or after its owner admits a source.
	/// Data completions still require the full admitted connection binding.
	/// # Errors
	/// Refuses foreign or retired work, expired authority, and invalid time.
	pub fn check_attempt(
		&mut self,
		now: Duration,
		attempt: ConnectionAttempt,
	) -> Result<(), RetryError> {
		match self.phase {
			Phase::Online(binding, _) if binding.attempt() == attempt => {
				self.check_completion(now, binding)
			}
			_ => self.check_connecting(now, attempt),
		}
	}

	/// Accepts separately refreshed route, SSH and source evidence for this attempt.
	///
	/// # Errors
	/// Refuses stale attempts, mixed admission evidence and expired or invalid time.
	pub fn admit(
		&mut self,
		now: Duration,
		attempt: ConnectionAttempt,
		evidence: ReconnectEvidence,
	) -> Result<ConnectionBinding, RetryError> {
		self.check_connecting(now, attempt)?;
		if evidence.route_checked_for != attempt
			|| evidence.ssh_authenticated_for != attempt
			|| evidence.source_checked_for != attempt
		{
			return Err(RetryError::StaleAdmission);
		}
		let binding = ConnectionBinding {
			attempt,
			source_epoch: evidence.source_epoch,
		};
		self.phase = Phase::Online(
			binding,
			Health {
				since: now,
				succeeded: false,
			},
		);
		Ok(binding)
	}

	/// Checks whether a completion still belongs to the active, authorized source view.
	/// The coordinator must also match request, job, entry and stage identity.
	///
	/// # Errors
	/// Refuses stale bindings, expired authority and invalid clocks.
	pub fn check_completion(
		&mut self,
		now: Duration,
		binding: ConnectionBinding,
	) -> Result<(), RetryError> {
		self.check_subject(FailureSubject::Connection(binding))?;
		self.observe_time(now)
	}

	/// Records successful activity and verified health for the current connection.
	/// A fresh dial alone cannot reset the penalty. Both 30 seconds of observed
	/// health and successful activity on this connection are required.
	///
	/// # Errors
	/// Refuses stale bindings, expired authority and invalid clocks.
	pub fn observe_health(
		&mut self,
		now: Duration,
		binding: ConnectionBinding,
		evidence: VerifiedHealth,
	) -> Result<(), RetryError> {
		self.check_completion(now, binding)?;
		if let Phase::Online(_, health) = &mut self.phase {
			health.succeeded |= matches!(
				evidence,
				VerifiedHealth::SuccessfulOperation | VerifiedHealth::AuthenticatedHeartbeat
			);
			if health.succeeded && now.saturating_sub(health.since) >= HEALTHY_RESET_AFTER {
				self.next_backoff_ms = INITIAL_BACKOFF_MS;
			}
		}
		Ok(())
	}

	/// Fences failed work and schedules or stops automatic retry by its known cause.
	/// A current uncertain effect stops this supervisor regardless of clock or grant
	/// validity. The coordinator must reconcile uncertain effects for old work too.
	///
	/// # Errors
	/// Refuses stale failure reports, expired authority and invalid clocks. A
	/// stale uncertain effect carries a distinct error and leaves the phase unchanged.
	pub fn failure(
		&mut self,
		now: Duration,
		subject: FailureSubject,
		failure: ConnectionFailure,
	) -> Result<FailureDecision, RetryError> {
		let current = self.check_subject(subject);
		match failure {
			ConnectionFailure::Transient {
				cause,
				jitter_sample,
			} => {
				current?;
				self.observe_time(now)?;
				let Some((wake_at, next_backoff_ms)) = retry_timing(
					now,
					self.grant_expires_at,
					self.next_backoff_ms,
					jitter_sample,
				) else {
					return Ok(self.stop_after_failure(RetryBlock::ClockRangeExhausted));
				};
				self.next_backoff_ms = next_backoff_ms;
				self.phase = Phase::Waiting(wake_at);
				Ok(FailureDecision::WaitUntil { wake_at, cause })
			}
			ConnectionFailure::Permanent(reason) => {
				current?;
				self.observe_time(now)?;
				Ok(self.stop_after_failure(RetryBlock::Permanent(reason)))
			}
			ConnectionFailure::EffectUncertain => {
				current.map_err(|_| RetryError::StaleUncertainEffect)?;
				Ok(self.stop_after_failure(RetryBlock::EffectUncertain))
			}
		}
	}

	fn check_subject(&self, subject: FailureSubject) -> Result<(), RetryError> {
		match (self.phase, subject) {
			(Phase::Connecting(current), FailureSubject::Attempt(observed))
				if current == observed =>
			{
				Ok(())
			}
			(Phase::Online(current, _), FailureSubject::Connection(observed))
				if current == observed =>
			{
				Ok(())
			}
			(Phase::Blocked(reason), _) => Err(RetryError::Blocked(reason)),
			_ => Err(RetryError::StaleWork),
		}
	}

	// Sample the clock when processing an event, regardless of when I/O completed.
	// Reject stale work first so it cannot update the current clock or phase.
	fn observe_time(&mut self, now: Duration) -> Result<(), RetryError> {
		if let Phase::Blocked(reason) = self.phase {
			return Err(RetryError::Blocked(reason));
		}
		if now < self.last_observation {
			return Err(self.block(RetryBlock::ClockRollback));
		}
		if now >= self.grant_expires_at {
			return Err(self.block(RetryBlock::GrantExpired));
		}
		self.last_observation = now;
		Ok(())
	}

	fn block(&mut self, reason: RetryBlock) -> RetryError {
		self.phase = Phase::Blocked(reason);
		RetryError::Blocked(reason)
	}

	fn stop_after_failure(&mut self, reason: RetryBlock) -> FailureDecision {
		self.phase = Phase::Blocked(reason);
		FailureDecision::Blocked(reason)
	}
}

#[cfg_attr(
	kani,
	kani::requires(matches!(
		ceiling_ms,
		1_000 | 2_000 | 4_000 | 8_000 | 16_000 | 32_000 | 60_000
	))
)]
#[cfg_attr(
	kani,
	kani::ensures(|delay| {
		delay.as_nanos() == crate::kani_checks::expected_delay_nanos(ceiling_ms, sample)
	})
)]
pub(crate) fn equal_jitter(ceiling_ms: u64, sample: u32) -> Duration {
	let half = ceiling_ms / 2;
	// The fixed policy caps `half` at 30,000 ms. Scaling a `u32` by the
	// inclusive window width fits in `u64`, including at both endpoints.
	let random_ms = (u64::from(sample) * (half + 1)) >> u32::BITS;
	Duration::from_millis(half + random_ms)
}

// Compute the complete timing decision before changing the live phase or penalty.
// An unrepresentable due time stops retry even if lease clipping would fit.
#[cfg_attr(
	kani,
	kani::requires(matches!(
		ceiling_ms,
		1_000 | 2_000 | 4_000 | 8_000 | 16_000 | 32_000 | 60_000
	))
)]
#[cfg_attr(
	kani,
	kani::ensures(|timing| {
		crate::kani_checks::timing_matches_by_parts(now, grant_expires_at, ceiling_ms, sample, *timing)
	})
)]
pub(crate) fn retry_timing(
	now: Duration,
	grant_expires_at: Duration,
	ceiling_ms: u64,
	sample: u32,
) -> Option<(Duration, u64)> {
	let delay = equal_jitter(ceiling_ms, sample);
	let due_at = now.checked_add(delay)?;
	let wake_at = due_at.min(grant_expires_at);
	let next_backoff_ms = ceiling_ms.saturating_mul(2).min(MAX_BACKOFF_MS);
	Some((wake_at, next_backoff_ms))
}

impl ConnectionAttempt {
	/// Returns the caller-reserved supervisor identity of this exact attempt.
	#[must_use]
	pub const fn owner(self) -> RetryOwner {
		self.owner
	}
}
