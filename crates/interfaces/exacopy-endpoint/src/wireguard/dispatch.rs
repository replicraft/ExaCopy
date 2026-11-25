//! Handoff from the application route guard to one embedded transport actor.

use std::fmt;
use std::num::{NonZeroU64, NonZeroU128};

use super::{
	AuthorizedInnerDial, InnerDial, ProfileRevision, RouteObservation, WireGuardDialError,
	WireGuardDialSession,
};

/// A received command for one exact inner dial, carrying the approved binding.
/// The actor consumes it against its own current route immediately before
/// starting the inner operation.
#[must_use]
pub struct EmbeddedDialCommand {
	instance: NonZeroU128,
	revision: ProfileRevision,
	generation: NonZeroU64,
	target: InnerDial,
}

impl EmbeddedDialCommand {
	/// Confirms current actor, revision and generation at the actual dial site.
	/// # Errors
	/// Blocks a pending command if the required route changed or became unavailable.
	pub fn start(self, current: RouteObservation) -> Result<InnerDial, WireGuardDialError> {
		current.require_embedded(self.instance, self.revision, self.generation)?;
		Ok(self.target)
	}
}

/// A trusted embedded-only connector. Its bounded queue carries opaque commands
/// into the actor which owns the qualified inner stack. Queue acceptance is
/// independent of connection completion. The actor must check each command with
/// its own observation immediately before initiation and retire stale results.
/// A connector implementation cannot acquire qualification by implementing
/// this interface.
pub trait EmbeddedDialConnector {
	/// A connector-owned handle for the queued operation.
	type Pending;
	/// Failure to transfer the command to the embedded actor.
	type Error;

	/// Observe the current binding of this connector's inner stack.
	fn observation(&self) -> RouteObservation;

	/// Takes ownership of an approved command for the embedded actor.
	/// # Errors
	/// Refuses a closed or full queue, keeping the dial unperformed.
	fn enqueue(&mut self, command: EmbeddedDialCommand) -> Result<Self::Pending, Self::Error>;
}

/// A rejected dispatch before any inner connection starts.
pub enum EmbeddedDispatchError<E> {
	/// The caller's permit or the current connector observation was rejected.
	Route(WireGuardDialError),
	/// The connector could not accept the command.
	Connector(E),
}

impl<E> fmt::Debug for EmbeddedDispatchError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Route(error) => formatter.debug_tuple("Route").field(error).finish(),
			Self::Connector(_) => formatter.debug_struct("Connector").finish_non_exhaustive(),
		}
	}
}

impl<E> fmt::Display for EmbeddedDispatchError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Route(error) => error.fmt(formatter),
			Self::Connector(_) => {
				formatter.write_str("the embedded connector refused the dial command")
			}
		}
	}
}

impl<E: std::error::Error + 'static> std::error::Error for EmbeddedDispatchError<E> {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Route(error) => Some(error),
			Self::Connector(error) => Some(error),
		}
	}
}

impl WireGuardDialSession<'_> {
	/// Sends a single-use permit to the selected embedded-only connector.
	/// # Errors
	/// Refuses a stale or invalid permit before enqueueing. A refused queue
	/// provides no fallback connection.
	pub fn dispatch<C: EmbeddedDialConnector>(
		&self,
		permit: AuthorizedInnerDial<'_>,
		connector: &mut C,
	) -> Result<C::Pending, EmbeddedDispatchError<C::Error>> {
		let target = self
			.consume(permit, connector.observation())
			.map_err(EmbeddedDispatchError::Route)?;
		connector
			.enqueue(EmbeddedDialCommand {
				instance: self.instance,
				revision: self.policy.revision,
				generation: self.generation,
				target,
			})
			.map_err(EmbeddedDispatchError::Connector)
	}
}

#[cfg(test)]
mod tests;
