use super::*;

const ACTOR: NonZeroU128 = NonZeroU128::MIN;
const GENERATION: NonZeroU64 = NonZeroU64::MIN;

fn later_generation() -> NonZeroU64 {
	GENERATION.checked_add(1).unwrap()
}

fn other_actor() -> NonZeroU128 {
	ACTOR.checked_add(1).unwrap()
}

fn revision() -> ProfileRevision {
	ProfileRevision::from_bytes([1; 32])
}

fn observed(generation: NonZeroU64) -> RouteObservation {
	RouteObservation::EmbeddedWireGuard {
		instance: ACTOR,
		revision: revision(),
		generation,
	}
}

fn endpoint(kind: InnerDialKind, address: &str) -> InnerDial {
	InnerDial::new(kind, address.parse().unwrap()).unwrap()
}

#[test]
fn mandatory_route_rejects_direct_system_and_unavailable_at_bind_or_consumption() {
	let ssh = endpoint(InnerDialKind::Stream, "10.1.2.3:22");
	let scope = [ssh];
	let policy = WireGuardDialPolicy::new(revision(), &scope).unwrap();
	let session =
		WireGuardDialSession::bind(&policy, ACTOR, GENERATION, observed(GENERATION)).unwrap();
	for (route, error) in [
		(
			RouteObservation::Direct,
			WireGuardDialError::EmbeddedRequired,
		),
		(
			RouteObservation::ExistingSystemNetwork,
			WireGuardDialError::EmbeddedRequired,
		),
		(
			RouteObservation::Unavailable,
			WireGuardDialError::Unavailable,
		),
	] {
		assert_eq!(
			WireGuardDialSession::bind(&policy, ACTOR, GENERATION, route).err(),
			Some(error)
		);
		assert_eq!(session.authorize(ssh, route).err(), Some(error));
		let permit = session.authorize(ssh, observed(GENERATION)).unwrap();
		assert_eq!(session.consume(permit, route).err(), Some(error));
	}
}

#[test]
fn exact_ipv4_ipv6_service_and_resolver_purposes_are_independent() {
	let ssh = endpoint(InnerDialKind::Stream, "[fd00::22]:22");
	let dns_udp = endpoint(InnerDialKind::DnsUdp, "10.1.2.3:53");
	let dns_tcp = endpoint(InnerDialKind::DnsTcp, "10.1.2.3:53");
	let scope = [ssh, dns_udp, dns_tcp];
	let policy = WireGuardDialPolicy::new(revision(), &scope).unwrap();
	let current = observed(GENERATION);
	let session = WireGuardDialSession::bind(&policy, ACTOR, GENERATION, current).unwrap();
	for granted in scope {
		let permit = session.authorize(granted, current).unwrap();
		let authorized = session.consume(permit, current).unwrap();
		assert_eq!(authorized.address(), granted.address());
		assert!(authorized.kind() == granted.kind());
	}
	for not_granted in [
		endpoint(InnerDialKind::Stream, "[fd00::22]:23"),
		endpoint(InnerDialKind::Stream, "[fd00::23]:22"),
		endpoint(InnerDialKind::Stream, "10.1.2.3:53"),
		endpoint(InnerDialKind::DnsUdp, "[fd00::22]:22"),
		endpoint(InnerDialKind::DnsTcp, "10.1.2.4:53"),
	] {
		assert_eq!(
			session.authorize(not_granted, current).err(),
			Some(WireGuardDialError::TargetNotGranted)
		);
	}
}

#[test]
fn udp_dns_grant_does_not_authorize_tcp_fallback() {
	let resolver = "10.1.2.3:53";
	let scope = [endpoint(InnerDialKind::DnsUdp, resolver)];
	let policy = WireGuardDialPolicy::new(revision(), &scope).unwrap();
	let current = observed(GENERATION);
	let session = WireGuardDialSession::bind(&policy, ACTOR, GENERATION, current).unwrap();
	assert_eq!(
		session
			.authorize(endpoint(InnerDialKind::DnsTcp, resolver), current)
			.err(),
		Some(WireGuardDialError::TargetNotGranted)
	);
}

#[test]
fn disconnect_invalidates_pending_permits_and_reconnect_requires_fresh_generation() {
	let ssh = endpoint(InnerDialKind::Stream, "10.1.2.3:22");
	let scope = [ssh];
	let policy = WireGuardDialPolicy::new(revision(), &scope).unwrap();
	let current = observed(GENERATION);
	let mut session = WireGuardDialSession::bind(&policy, ACTOR, GENERATION, current).unwrap();
	let lost = session.authorize(ssh, current).unwrap();
	let stale = session.authorize(ssh, current).unwrap();
	session.disconnect();
	assert_eq!(
		session.consume(lost, current).err(),
		Some(WireGuardDialError::Unavailable)
	);
	assert_eq!(
		session.reconnect(GENERATION, current),
		Err(WireGuardDialError::StaleGeneration)
	);
	let later = later_generation();
	assert_eq!(
		session.reconnect(later, RouteObservation::Direct),
		Err(WireGuardDialError::EmbeddedRequired)
	);
	assert_eq!(
		session.authorize(ssh, current).err(),
		Some(WireGuardDialError::Unavailable)
	);
	let next = observed(later);
	session.reconnect(later, next).unwrap();
	assert_eq!(
		session.consume(stale, next).err(),
		Some(WireGuardDialError::StaleGeneration)
	);
	assert_eq!(
		session.authorize(ssh, current).err(),
		Some(WireGuardDialError::StaleGeneration)
	);
	assert!(
		session
			.consume(session.authorize(ssh, next).unwrap(), next)
			.is_ok()
	);
}

#[test]
fn reconnect_refuses_changed_revision_and_actor_even_with_approved_target() {
	let ssh = endpoint(InnerDialKind::Stream, "10.1.2.3:22");
	let scope = [ssh];
	let policy = WireGuardDialPolicy::new(revision(), &scope).unwrap();
	let mut session =
		WireGuardDialSession::bind(&policy, ACTOR, GENERATION, observed(GENERATION)).unwrap();
	let later = later_generation();
	let changed = RouteObservation::EmbeddedWireGuard {
		instance: ACTOR,
		revision: ProfileRevision::from_bytes([2; 32]),
		generation: later,
	};
	assert_eq!(
		session.reconnect(later, changed),
		Err(WireGuardDialError::RevisionChanged)
	);
	let other = RouteObservation::EmbeddedWireGuard {
		instance: other_actor(),
		revision: revision(),
		generation: later,
	};
	assert_eq!(
		session.reconnect(later, other),
		Err(WireGuardDialError::ActorChanged)
	);
	assert_eq!(
		session.authorize(ssh, observed(later)).err(),
		Some(WireGuardDialError::Unavailable)
	);
}

#[test]
fn same_addresses_cannot_transfer_permits_across_actors_or_distinct_grants() {
	let ssh = endpoint(InnerDialKind::Stream, "10.1.2.3:22");
	let scope = [ssh];
	let first_policy = WireGuardDialPolicy::new(revision(), &scope).unwrap();
	let second_policy = WireGuardDialPolicy::new(revision(), &scope).unwrap();
	let current = observed(GENERATION);
	let first_session =
		WireGuardDialSession::bind(&first_policy, ACTOR, GENERATION, current).unwrap();
	let wrong_scope =
		WireGuardDialSession::bind(&second_policy, ACTOR, GENERATION, current).unwrap();
	let other = RouteObservation::EmbeddedWireGuard {
		instance: other_actor(),
		revision: revision(),
		generation: GENERATION,
	};
	let wrong_actor =
		WireGuardDialSession::bind(&first_policy, other_actor(), GENERATION, other).unwrap();
	for (other_session, observation) in [(wrong_scope, current), (wrong_actor, other)] {
		let permit = first_session.authorize(ssh, current).unwrap();
		assert_eq!(
			other_session.consume(permit, observation).err(),
			Some(WireGuardDialError::ActorChanged)
		);
	}
}

#[test]
fn target_limits_and_ambiguous_ip_representations_are_refused() {
	for address in [
		"10.1.2.3:0",
		"0.0.0.0:22",
		"[::]:22",
		"[::ffff:10.1.2.3]:22",
		"[fe80::1%2]:22",
		"224.0.0.1:53",
		"255.255.255.255:22",
	] {
		assert!(InnerDial::new(InnerDialKind::Stream, address.parse().unwrap()).is_none());
	}
	let ssh = endpoint(InnerDialKind::Stream, "10.1.2.3:22");
	let targets = [ssh; MAX_WIREGUARD_DIAL_TARGETS + 1];
	assert!(WireGuardDialPolicy::new(revision(), &targets[..MAX_WIREGUARD_DIAL_TARGETS]).is_ok());
	assert_eq!(
		WireGuardDialPolicy::new(revision(), &targets).err(),
		Some(WireGuardDialError::TargetLimit)
	);
	assert_eq!(
		WireGuardDialPolicy::new(revision(), &[]).err(),
		Some(WireGuardDialError::TargetLimit)
	);
}
