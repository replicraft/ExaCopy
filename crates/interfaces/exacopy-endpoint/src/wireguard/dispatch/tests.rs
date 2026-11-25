use super::*;
use crate::wireguard::{InnerDialKind, WireGuardDialPolicy};

const ACTOR: NonZeroU128 = NonZeroU128::MIN;
const GENERATION: NonZeroU64 = NonZeroU64::MIN;
const REVISION: ProfileRevision = ProfileRevision::from_bytes([1; 32]);

fn observed(generation: NonZeroU64) -> RouteObservation {
	RouteObservation::EmbeddedWireGuard {
		instance: ACTOR,
		revision: REVISION,
		generation,
	}
}

fn target(kind: InnerDialKind, address: &str) -> InnerDial {
	InnerDial::new(kind, address.parse().unwrap()).unwrap()
}

struct MockActor {
	current: RouteObservation,
	pending: Option<EmbeddedDialCommand>,
	started: usize,
}

#[derive(Debug)]
struct QueueFull;

impl EmbeddedDialConnector for MockActor {
	type Pending = ();
	type Error = QueueFull;

	fn observation(&self) -> RouteObservation {
		self.current
	}

	fn enqueue(&mut self, command: EmbeddedDialCommand) -> Result<(), QueueFull> {
		if self.pending.is_some() {
			return Err(QueueFull);
		}
		self.pending = Some(command);
		Ok(())
	}
}

impl MockActor {
	fn new() -> Self {
		Self {
			current: observed(GENERATION),
			pending: None,
			started: 0,
		}
	}

	fn start(&mut self) -> Result<InnerDial, WireGuardDialError> {
		let target = self
			.pending
			.take()
			.expect("expected mock dial")
			.start(self.current)?;
		self.started += 1;
		Ok(target)
	}
}

#[test]
fn bounded_queue_preserves_the_approved_dns_scope() {
	let dns = target(InnerDialKind::DnsTcp, "[fd00::53]:53");
	let scope = [dns];
	let policy = WireGuardDialPolicy::new(REVISION, &scope).unwrap();
	let current = observed(GENERATION);
	let session = WireGuardDialSession::bind(&policy, ACTOR, GENERATION, current).unwrap();
	let mut actor = MockActor::new();
	session
		.dispatch(session.authorize(dns, current).unwrap(), &mut actor)
		.unwrap();
	assert_eq!(actor.started, 0);
	assert!(matches!(
		session.dispatch(session.authorize(dns, current).unwrap(), &mut actor),
		Err(EmbeddedDispatchError::Connector(QueueFull))
	));
	let started = actor.start().unwrap();
	assert_eq!(actor.started, 1);
	assert!(started == dns);
}

#[test]
fn queueing_never_replaces_the_actor_start_check() {
	let ssh = target(InnerDialKind::Stream, "10.1.2.3:22");
	let scope = [ssh];
	let policy = WireGuardDialPolicy::new(REVISION, &scope).unwrap();
	let current = observed(GENERATION);
	let session = WireGuardDialSession::bind(&policy, ACTOR, GENERATION, current).unwrap();
	for (route, error) in [
		(
			RouteObservation::Direct,
			WireGuardDialError::EmbeddedRequired,
		),
		(
			RouteObservation::Unavailable,
			WireGuardDialError::Unavailable,
		),
		(
			observed(GENERATION.checked_add(1).unwrap()),
			WireGuardDialError::StaleGeneration,
		),
	] {
		let mut actor = MockActor::new();
		session
			.dispatch(session.authorize(ssh, current).unwrap(), &mut actor)
			.unwrap();
		actor.current = route;
		assert_eq!(actor.start().err(), Some(error));
		assert!(actor.pending.is_none());
		assert_eq!(actor.started, 0);
		assert!(matches!(
			session.dispatch(session.authorize(ssh, current).unwrap(), &mut actor),
			Err(EmbeddedDispatchError::Route(observed_error)) if observed_error == error
		));
		assert!(actor.pending.is_none());
	}
}
