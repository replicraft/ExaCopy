//! Admission for application dials that require one approved embedded WireGuard route.
//!
//! The connector owner supplies current route observations and consumes permits
//! through its embedded dial factory. This module does not open sockets, resolve
//! names, parse credentials, or establish the transport's routing guarantees.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU64, NonZeroU128};

mod dispatch;
#[cfg(test)]
mod tests;

pub use dispatch::{EmbeddedDialCommand, EmbeddedDialConnector, EmbeddedDispatchError};

/// Upper bound for exact inner service and resolver targets in one approved scope.
pub const MAX_WIREGUARD_DIAL_TARGETS: usize = 256;

/// The digest of an independently approved embedded profile revision.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProfileRevision([u8; 32]);

impl ProfileRevision {
	/// Wraps the exact digest provided by the profile owner.
	#[must_use]
	pub const fn from_bytes(digest: [u8; 32]) -> Self {
		Self(digest)
	}
}

/// The route actor and generation observed by the owning connector or supervisor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RouteObservation {
	/// An available route through the specified embedded actor and approved revision.
	EmbeddedWireGuard {
		/// Unique actor identity reserved independently by the route supervisor.
		instance: NonZeroU128,
		/// Revision actually bound to the observed route actor.
		revision: ProfileRevision,
		/// Current generation of that route actor.
		generation: NonZeroU64,
	},
	/// An explicit direct route.
	Direct,
	/// An operating system route without an embedded-route guarantee.
	ExistingSystemNetwork,
	/// The required route is unavailable.
	Unavailable,
}

/// The operation to authorize on an exact inner address and port.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InnerDialKind {
	/// An application stream, including SSH/SFTP and TLS over inner TCP.
	Stream,
	/// A DNS query through inner UDP.
	DnsUdp,
	/// A DNS query or fallback through inner TCP.
	DnsTcp,
}

/// One literal, unicast inner target and its authorized use.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InnerDial {
	kind: InnerDialKind,
	address: SocketAddr,
}

impl InnerDial {
	/// Rejects targets that cannot be used as exact portable inner addresses.
	#[must_use]
	pub fn new(kind: InnerDialKind, address: SocketAddr) -> Option<Self> {
		let ip = address.ip();
		if address.port() == 0 || ip.is_unspecified() || ip.is_multicast() {
			return None;
		}
		match address {
			SocketAddr::V4(v4) if v4.ip().is_broadcast() => return None,
			SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0 => return None,
			_ => {}
		}
		if matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some()) {
			return None;
		}
		Some(Self { kind, address })
	}

	/// The exact approved dial target.
	#[must_use]
	pub const fn address(self) -> SocketAddr {
		self.address
	}

	/// The purpose and inner transport to which this address is scoped.
	#[must_use]
	pub const fn kind(self) -> InnerDialKind {
		self.kind
	}
}

/// The frozen authority inputs for one application's embedded route scope.
pub struct WireGuardDialPolicy<'scope> {
	revision: ProfileRevision,
	targets: &'scope [InnerDial],
}

impl<'scope> WireGuardDialPolicy<'scope> {
	/// Binds a previously approved revision to a bounded set of targets.
	/// # Errors
	/// Refuses an empty or oversized scope.
	pub const fn new(
		revision: ProfileRevision,
		targets: &'scope [InnerDial],
	) -> Result<Self, WireGuardDialError> {
		if targets.is_empty() || targets.len() > MAX_WIREGUARD_DIAL_TARGETS {
			return Err(WireGuardDialError::TargetLimit);
		}
		Ok(Self { revision, targets })
	}
}

/// A generation-bound application authority for one embedded route actor.
///
/// The owning connector must supply truthful observations and serialize this
/// state with actor transitions and the immediate consumption of each permit.
/// Inner DNS results, peer routing and packet flow still require independent
/// enforcement by the qualified embedded transport.
pub struct WireGuardDialSession<'scope> {
	policy: &'scope WireGuardDialPolicy<'scope>,
	instance: NonZeroU128,
	generation: NonZeroU64,
	active: bool,
}

impl<'scope> WireGuardDialSession<'scope> {
	/// Binds the scope to the supervisor's actor and initial generation.
	/// # Errors
	/// Refuses unavailable, nonembedded or mismatched observations.
	pub fn bind(
		policy: &'scope WireGuardDialPolicy<'scope>,
		instance: NonZeroU128,
		generation: NonZeroU64,
		observation: RouteObservation,
	) -> Result<Self, WireGuardDialError> {
		let session = Self {
			policy,
			instance,
			generation,
			active: true,
		};
		session.check_observation(generation, observation)?;
		Ok(session)
	}

	/// Invalidates pending permits after a loss of the route.
	pub fn disconnect(&mut self) {
		self.active = false;
	}

	/// Advances to a strictly later generation of the same actor and revision.
	/// # Errors
	/// Refuses stale generations or unavailable, changed and nonembedded routes.
	/// A refused reconnection leaves the session blocked.
	pub fn reconnect(
		&mut self,
		generation: NonZeroU64,
		observation: RouteObservation,
	) -> Result<(), WireGuardDialError> {
		self.disconnect();
		if generation <= self.generation {
			return Err(WireGuardDialError::StaleGeneration);
		}
		self.check_observation(generation, observation)?;
		self.generation = generation;
		self.active = true;
		Ok(())
	}

	/// Authorizes one exact target for the observed active embedded route.
	/// # Errors
	/// Refuses a changed or unavailable route, stale generation or ungranted target.
	pub fn authorize(
		&self,
		request: InnerDial,
		observation: RouteObservation,
	) -> Result<AuthorizedInnerDial<'scope>, WireGuardDialError> {
		self.check_active(observation)?;
		if !self.policy.targets.contains(&request) {
			return Err(WireGuardDialError::TargetNotGranted);
		}
		Ok(AuthorizedInnerDial {
			policy: self.policy,
			instance: self.instance,
			generation: self.generation,
			request,
		})
	}

	/// Consumes a permit immediately before the embedded connector's dial.
	/// # Errors
	/// Refuses an old permit, another scope or actor, or a changed current route.
	pub fn consume(
		&self,
		permit: AuthorizedInnerDial<'_>,
		observation: RouteObservation,
	) -> Result<InnerDial, WireGuardDialError> {
		if !std::ptr::eq(self.policy, permit.policy) || self.instance != permit.instance {
			return Err(WireGuardDialError::ActorChanged);
		}
		if self.generation != permit.generation {
			return Err(WireGuardDialError::StaleGeneration);
		}
		self.check_active(observation)?;
		Ok(permit.request)
	}

	fn check_active(&self, observation: RouteObservation) -> Result<(), WireGuardDialError> {
		if !self.active {
			return Err(WireGuardDialError::Unavailable);
		}
		self.check_observation(self.generation, observation)
	}

	fn check_observation(
		&self,
		generation: NonZeroU64,
		observation: RouteObservation,
	) -> Result<(), WireGuardDialError> {
		observation.require_embedded(self.instance, self.policy.revision, generation)
	}
}

impl RouteObservation {
	fn require_embedded(
		self,
		expected_instance: NonZeroU128,
		expected_revision: ProfileRevision,
		generation: NonZeroU64,
	) -> Result<(), WireGuardDialError> {
		match self {
			RouteObservation::EmbeddedWireGuard {
				instance,
				revision,
				generation: current,
			} => {
				if expected_revision != revision {
					return Err(WireGuardDialError::RevisionChanged);
				}
				if expected_instance != instance {
					return Err(WireGuardDialError::ActorChanged);
				}
				if generation != current {
					return Err(WireGuardDialError::StaleGeneration);
				}
				Ok(())
			}
			RouteObservation::Direct | RouteObservation::ExistingSystemNetwork => {
				Err(WireGuardDialError::EmbeddedRequired)
			}
			RouteObservation::Unavailable => Err(WireGuardDialError::Unavailable),
		}
	}
}

/// A single-use dial permit scoped to the exact embedded actor and grant.
#[must_use]
pub struct AuthorizedInnerDial<'scope> {
	policy: &'scope WireGuardDialPolicy<'scope>,
	instance: NonZeroU128,
	generation: NonZeroU64,
	request: InnerDial,
}

/// A fail-closed application route decision.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum WireGuardDialError {
	/// The scope is empty or exceeds the bounded target count.
	TargetLimit,
	/// The supplied route does not provide embedded WireGuard.
	EmbeddedRequired,
	/// The bound route is unavailable or has been invalidated.
	Unavailable,
	/// The observed profile revision differs from the approved revision.
	RevisionChanged,
	/// The actor or authority does not match the permit or approved session.
	ActorChanged,
	/// The operation belongs to another generation.
	StaleGeneration,
	/// The exact endpoint and use are outside the approved scope.
	TargetNotGranted,
}

impl fmt::Display for WireGuardDialError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::TargetLimit => "embedded route scope is empty or exceeds the target limit",
			Self::EmbeddedRequired => "the requested connection requires embedded WireGuard",
			Self::Unavailable => "the required embedded route is unavailable",
			Self::RevisionChanged => "the embedded profile revision changed",
			Self::ActorChanged => "the embedded route authority changed",
			Self::StaleGeneration => "the embedded route generation does not match",
			Self::TargetNotGranted => "the inner connection is outside its approved scope",
		})
	}
}

impl std::error::Error for WireGuardDialError {}
