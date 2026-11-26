use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use exacopy_endpoint::wireguard::{ProfileRevision, RouteObservation};
use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_wireguard::protocol::PeerBinding;
use exacopy_wireguard::stack::RouteRevocation;
use exacopy_wireguard::udp::{RouteOwner, TcpRouteOwner};

use super::super::route_lifetime::RouteActivity;
use super::RemoteGrant;

pub(super) struct EmbeddedOwner {
	grant: Arc<RemoteGrant>,
	scope: RemoteScopeDigest,
	binding: RouteObservation,
	activity: Arc<RouteActivity>,
	claimed: AtomicBool,
	revocation: RouteRevocation,
}

impl EmbeddedOwner {
	pub(super) fn new(
		grant: Arc<RemoteGrant>,
		scope: RemoteScopeDigest,
		binding: PeerBinding,
		activity: Arc<RouteActivity>,
		revocation: RouteRevocation,
	) -> Self {
		Self {
			grant,
			scope,
			binding: RouteObservation::EmbeddedWireGuard {
				instance: binding.actor,
				revision: ProfileRevision::from_bytes(binding.revision),
				generation: binding.generation,
			},
			activity,
			claimed: AtomicBool::new(false),
			revocation,
		}
	}
}

impl RouteOwner for EmbeddedOwner {
	fn with_observation<T>(&self, observe: impl FnOnce(RouteObservation) -> T) -> T {
		self.activity
			.with_grant(&self.grant, self.scope, |current| {
				observe(if current {
					self.binding
				} else {
					RouteObservation::Unavailable
				})
			})
	}

	fn claim_generation(&self, binding: RouteObservation) -> bool {
		self.with_observation(|current| {
			binding != RouteObservation::Unavailable
				&& binding == current
				&& !self.claimed.swap(true, Ordering::AcqRel)
		})
	}
}

impl TcpRouteOwner for EmbeddedOwner {
	fn stream_revocation(&self, binding: RouteObservation) -> Option<RouteRevocation> {
		self.with_observation(|current| {
			(binding != RouteObservation::Unavailable
				&& binding == current
				&& self.claimed.load(Ordering::Acquire))
			.then(|| self.revocation.clone())
		})
	}
}

#[cfg(test)]
mod tests {
	use std::num::{NonZeroU64, NonZeroU128};
	use std::time::{Duration, Instant};

	use super::super::super::route_lifetime::RouteLease;
	use super::*;

	#[test]
	fn exact_generation_is_claimed_once_and_route_local_stop_preserves_the_grant() {
		let scope = RemoteScopeDigest::from_bytes([1; 32]);
		let grant = Arc::new(
			RemoteGrant::new(scope, [2; 32], Instant::now() + Duration::from_secs(30)).unwrap(),
		);
		let binding = PeerBinding {
			revision: [3; 32],
			actor: NonZeroU128::MIN,
			generation: NonZeroU64::MIN,
		};
		let lease = RouteLease::new();
		let owner = EmbeddedOwner::new(
			Arc::clone(&grant),
			scope,
			binding,
			lease.activity(),
			RouteRevocation::new(binding),
		);
		let current = owner.with_observation(|observation| observation);
		let foreign = RouteObservation::EmbeddedWireGuard {
			instance: binding.actor,
			revision: ProfileRevision::from_bytes(binding.revision),
			generation: binding.generation.saturating_add(1),
		};
		assert!(owner.stream_revocation(current).is_none());
		assert!(!owner.claim_generation(foreign));
		assert!(owner.claim_generation(current));
		assert!(!owner.claim_generation(current));
		assert!(owner.stream_revocation(current).is_some());
		assert!(owner.stream_revocation(foreign).is_none());
		drop(lease);
		assert!(grant.check_source(scope).is_ok());
		assert!(owner.with_observation(|observation| observation == RouteObservation::Unavailable));
		assert!(!owner.claim_generation(current));
		assert!(owner.stream_revocation(current).is_none());
	}
}
