use std::fmt;
use std::num::NonZeroU128;
use std::time::Duration;

use super::{ConnectionAttempt, ConnectionBinding};

/// The outcome of polling for one connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum RetryDecision {
	/// Start a fresh attempt using this generation.
	Start(ConnectionAttempt),
	/// Sleep until this reading on the caller's monotonic clock before polling again.
	WaitUntil(Duration),
}

/// The in-flight work to which a failure is attributable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureSubject {
	/// Route, transport, authentication or source admission is still in progress.
	Attempt(ConnectionAttempt),
	/// The connection and its admitted source epoch are in use.
	Connection(ConnectionBinding),
}

/// A causal observation that permits another attempt without replaying an effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransientFailure {
	/// The required route is temporarily unavailable without an authority change.
	RouteUnavailable,
	/// The transport or channel disconnected before any effect became uncertain.
	TransportInterrupted,
	/// A connection setup or read-only operation reached its timeout.
	NonMutatingTimeout,
}

/// A failure that requires action before a caller can explicitly authorize new work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermanentFailure {
	/// The peer definitively rejected the selected credential revision.
	CredentialRejected,
	/// The credential broker could not supply an authorized credential.
	CredentialUnavailable,
	/// The peer identity or host trust check was refused.
	HostIdentityRefused,
	/// The required route would leave the approved endpoint or policy.
	RouteAuthorityRefused,
	/// The grant owner revoked the previously supplied lease.
	GrantRevoked,
	/// The requested operation or capability is unsupported.
	UnsupportedCapability,
	/// A required profile or configuration was invalid.
	InvalidConfiguration,
	/// The peer or namespace refused the requested access.
	PermissionDenied,
	/// A persistent resource error requires action, such as quota exhaustion.
	ResourceBlocked,
	/// The observed source no longer matches the approved source view.
	SourceChanged,
	/// Required integrity evidence failed.
	IntegrityFailure,
}

/// The adapter's classified observation about a failed attempt or connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionFailure {
	/// A safe, transient loss with one uniformly sampled random `u32` for equal jitter.
	Transient {
		/// The observed temporary failure.
		cause: TransientFailure,
		/// A fresh sample from the caller's injected randomness source.
		jitter_sample: u32,
	},
	/// An explicit refusal that ends automatic retry.
	Permanent(PermanentFailure),
	/// A prior request may already have taken effect and needs reconciliation.
	EffectUncertain,
}

/// The supervisor's response after attributing a failure to current work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum FailureDecision {
	/// The old work was fenced and a timer may trigger a new attempt.
	WaitUntil {
		/// The wake time on the injected monotonic clock.
		wake_at: Duration,
		/// The transient failure recorded for the caller's diagnostics.
		cause: TransientFailure,
	},
	/// The old work was fenced and the supervisor cannot schedule another attempt.
	Blocked(RetryBlock),
}

/// Evidence observed on a still-healthy admitted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedHealth {
	/// An independent health check establishes that the session has remained healthy.
	Healthy,
	/// One verified application operation completed successfully.
	SuccessfulOperation,
	/// A current, authenticated idle heartbeat completed successfully.
	AuthenticatedHeartbeat,
}

/// A terminal reason for refusing further attempts from this supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryBlock {
	/// The adapter classified a permanent failure.
	Permanent(PermanentFailure),
	/// A previously issued operation requires reconciliation.
	EffectUncertain,
	/// The supervisor's fixed grant lease reached its exclusive expiry.
	GrantExpired,
	/// The injected monotonic clock rolled back.
	ClockRollback,
	/// A retry deadline would be outside the clock representation.
	ClockRangeExhausted,
	/// The unique generation counter cannot advance without reuse.
	GenerationExhausted,
}

/// The supplied event could not be admitted in the current supervisor state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryError {
	/// An attempt is already running, or an admitted connection is still active.
	Busy,
	/// The event belongs to a different owner, generation, phase or source epoch.
	StaleWork,
	/// An old operation may already have taken effect and requires separate reconciliation.
	StaleUncertainEffect,
	/// Route, SSH and source checks must each belong to the current attempt.
	StaleAdmission,
	/// The supervisor reached a terminal state.
	Blocked(RetryBlock),
}

impl fmt::Display for RetryError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Busy => formatter.write_str("a connection attempt or session is already active"),
			Self::StaleWork => formatter.write_str("connection work belongs to a stale attempt"),
			Self::StaleUncertainEffect => {
				formatter.write_str("stale connection work requires reconciliation")
			}
			Self::StaleAdmission => formatter.write_str("connection admission is stale"),
			Self::Blocked(reason) => write!(formatter, "connection retry blocked: {reason:?}"),
		}
	}
}

impl std::error::Error for RetryError {}

/// A caller-reserved unique identifier for one supervisor lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetryOwner(NonZeroU128);

impl RetryOwner {
	/// Wraps a value that the caller reserves uniquely among controller lifetimes.
	#[must_use]
	pub const fn new(id: NonZeroU128) -> Self {
		Self(id)
	}

	/// Returns the full caller-reserved supervisor identifier without narrowing.
	#[must_use]
	pub const fn id(self) -> NonZeroU128 {
		self.0
	}
}
