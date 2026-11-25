use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU64, NonZeroU128};
use std::rc::Rc;

use exacopy_endpoint::wireguard::{
	EmbeddedDialConnector, InnerDialKind, WireGuardDialPolicy, WireGuardDialSession,
};

use super::*;
use crate::protocol::{PeerAddresses, PublicKey, StaticSecret};

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 45, 1, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 45, 1, 2);
const SHORT_WAIT: Duration = Duration::from_millis(25);
const BIND_LOOPBACK: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

#[derive(Clone)]
struct MockRoute {
	current: Rc<Cell<RouteObservation>>,
	revoke_after_observation: Rc<Cell<bool>>,
	last_claimed: Rc<Cell<Option<NonZeroU64>>>,
}

impl MockRoute {
	fn new(binding: PeerBinding) -> Self {
		Self {
			current: Rc::new(Cell::new(route_binding(binding))),
			revoke_after_observation: Rc::new(Cell::new(false)),
			last_claimed: Rc::new(Cell::new(None)),
		}
	}
}

impl RouteOwner for MockRoute {
	fn with_observation<T>(&self, observe: impl FnOnce(RouteObservation) -> T) -> T {
		let result = observe(self.current.get());
		if self.revoke_after_observation.replace(false) {
			self.current.set(RouteObservation::Unavailable);
		}
		result
	}

	fn claim_generation(&self, binding: RouteObservation) -> bool {
		let RouteObservation::EmbeddedWireGuard { generation, .. } = binding else {
			return false;
		};
		if binding != self.current.get()
			|| self
				.last_claimed
				.get()
				.is_some_and(|claimed| generation <= claimed)
		{
			return false;
		}
		self.last_claimed.set(Some(generation));
		true
	}
}

fn run(test: impl std::future::Future<Output = ()>) {
	tokio::runtime::Builder::new_current_thread()
		.enable_io()
		.enable_time()
		.build()
		.unwrap()
		.block_on(test);
}

fn binding(generation: u64) -> PeerBinding {
	PeerBinding {
		actor: NonZeroU128::MIN,
		revision: [1; 32],
		generation: NonZeroU64::new(generation).unwrap(),
	}
}

fn protocol(outer: SocketAddr, initiator: bool, generation: PeerBinding) -> ProtocolPeer {
	let (local_key, remote_key, local, remote) = if initiator {
		(111, 123, LOCAL, REMOTE)
	} else {
		(123, 111, REMOTE, LOCAL)
	};
	ProtocolPeer::new(
		generation,
		PeerAddresses {
			outer,
			local: local.into(),
			remote: remote.into(),
		},
		StaticSecret::from([local_key; 32]),
		PublicKey::from(&StaticSecret::from([remote_key; 32])),
	)
	.unwrap()
}

async fn socket_pair() -> (UdpSocket, UdpSocket) {
	let first = UdpSocket::bind(BIND_LOOPBACK).await.unwrap();
	let second = UdpSocket::bind(BIND_LOOPBACK).await.unwrap();
	first.connect(second.local_addr().unwrap()).await.unwrap();
	second.connect(first.local_addr().unwrap()).await.unwrap();
	first.writable().await.unwrap();
	second.writable().await.unwrap();
	(first, second)
}

async fn peers() -> (MockRoute, UdpPeer<MockRoute>, UdpPeer<MockRoute>) {
	let (socket, target) = socket_pair().await;
	let generation = binding(1);
	let owner = MockRoute::new(generation);
	let first_protocol = protocol(socket.peer_addr().unwrap(), true, generation);
	let second_protocol = protocol(target.peer_addr().unwrap(), false, generation);
	(
		owner.clone(),
		UdpPeer::from_connected(owner, socket, first_protocol).unwrap(),
		UdpPeer::from_connected(MockRoute::new(generation), target, second_protocol).unwrap(),
	)
}

async fn handshake(first: &mut UdpPeer<MockRoute>, second: &mut UdpPeer<MockRoute>) {
	let mut output = [0; MAX_DATAGRAM_BYTES];
	assert!(matches!(first.initiate(&mut output), Ok(UdpProgress::Sent)));
	for peer in [&mut *second, &mut *first] {
		assert!(matches!(
			receive_control(peer, &mut output).await,
			UdpProgress::Sent
		));
	}
	assert!(matches!(
		receive_control(second, &mut output).await,
		UdpProgress::Idle
	));
	assert!(
		first
			.active
			.as_ref()
			.unwrap()
			.protocol
			.observation()
			.has_session
	);
	assert!(
		second
			.active
			.as_ref()
			.unwrap()
			.protocol
			.observation()
			.has_session
	);
}

async fn receive_control(
	peer: &mut UdpPeer<MockRoute>,
	output: &mut [u8; MAX_DATAGRAM_BYTES],
) -> UdpProgress<'static> {
	// A consumed datagram with no output is distinct from stale relay readiness.
	for _ in 0..3 {
		match peer.receive_one(MAX_RECEIVE_WAIT, output).await.unwrap() {
			UdpProgress::NoDatagram => {}
			UdpProgress::Idle => return UdpProgress::Idle,
			UdpProgress::Sent => return UdpProgress::Sent,
			_ => panic!("expected one handshake control operation"),
		}
	}
	panic!("expected a loopback handshake datagram");
}

fn fixture_ip(source: Ipv4Addr, destination: Ipv4Addr) -> [u8; 24] {
	let mut packet = [0; 24];
	packet[0] = 0x45;
	packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
	packet[12..16].copy_from_slice(&source.octets());
	packet[16..20].copy_from_slice(&destination.octets());
	packet[20..].copy_from_slice(b"test");
	packet
}

async fn exchange(source: &mut UdpPeer<MockRoute>, dest: &mut UdpPeer<MockRoute>, packet: &[u8]) {
	let mut output = [0; MAX_DATAGRAM_BYTES];
	assert!(matches!(
		source.send_inner(packet, &mut output),
		Ok(UdpProgress::Sent)
	));
	for _ in 0..3 {
		match dest
			.receive_one(MAX_RECEIVE_WAIT, &mut output)
			.await
			.unwrap()
		{
			UdpProgress::NoDatagram => {}
			UdpProgress::Inner(bytes) if bytes == packet => return,
			_ => panic!("unexpected packet after loopback encryption"),
		}
	}
	panic!("expected an authenticated loopback packet");
}

#[test]
fn loopback_connected_peers_handshake_and_exchange_both_directions() {
	run(async {
		let (_, mut first, mut second) = peers().await;
		let mut output = [0; MAX_DATAGRAM_BYTES];
		assert!(matches!(
			first.send_inner(&fixture_ip(LOCAL, REMOTE), &mut output),
			Err(UdpError::Protocol(ProtocolError::NoSession))
		));
		handshake(&mut first, &mut second).await;

		exchange(&mut first, &mut second, &fixture_ip(LOCAL, REMOTE)).await;
		exchange(&mut second, &mut first, &fixture_ip(REMOTE, LOCAL)).await;
	});
}

#[test]
fn rejects_unconnected_wrong_peer_foreign_sender_and_oversized_datagram() {
	run(async {
		let (socket, remote) = socket_pair().await;
		let remote_address = remote.local_addr().unwrap();
		let generation = binding(1);
		let caller = MockRoute::new(generation);
		let unconnected = UdpSocket::bind(BIND_LOOPBACK).await.unwrap();
		let peer = protocol(remote_address, true, generation);
		assert!(matches!(
			UdpPeer::from_connected(caller.clone(), unconnected, peer),
			Err(UdpError::Socket(SocketPhase::Admit, _))
		));
		let (wrong_socket, _) = socket_pair().await;
		let peer = protocol(remote_address, true, generation);
		assert!(matches!(
			UdpPeer::from_connected(caller.clone(), wrong_socket, peer),
			Err(UdpError::EndpointMismatch)
		));

		let actor_address = socket.local_addr().unwrap();
		let peer = protocol(remote_address, true, generation);
		let mut actor = UdpPeer::from_connected(caller, socket, peer).unwrap();
		let foreign = UdpSocket::bind(BIND_LOOPBACK).await.unwrap();
		foreign.connect(actor_address).await.unwrap();
		foreign.send(b"unexpected").await.unwrap();
		let mut output = [0; MAX_DATAGRAM_BYTES];
		assert!(matches!(
			actor
				.receive_one(MAX_RECEIVE_WAIT + SHORT_WAIT, &mut output)
				.await,
			Err(UdpError::WaitLimit)
		));
		assert!(matches!(
			actor.receive_one(SHORT_WAIT, &mut output).await,
			Ok(UdpProgress::NoDatagram)
		));
		remote.send(&[0; MAX_DATAGRAM_BYTES + 1]).await.unwrap();
		for _ in 0..3 {
			match actor.receive_one(MAX_RECEIVE_WAIT, &mut output).await {
				Ok(UdpProgress::NoDatagram) => {}
				Err(UdpError::DatagramLimit) => return,
				_ => panic!("oversized outer datagram received an invalid disposition"),
			}
		}
		panic!("expected an oversized loopback datagram");
	});
}

#[test]
fn revocation_between_protocol_output_and_socket_send_discards_datagram() {
	run(async {
		let (socket, remote) = socket_pair().await;
		let generation = binding(1);
		let route = MockRoute::new(generation);
		let protocol = protocol(socket.peer_addr().unwrap(), true, generation);
		let mut peer = UdpPeer::from_connected(route.clone(), socket, protocol).unwrap();
		route.revoke_after_observation.set(true);

		let mut output = [0; MAX_DATAGRAM_BYTES];
		assert!(matches!(
			peer.initiate(&mut output),
			Err(UdpError::RouteChanged)
		));
		assert!(
			tokio::time::timeout(SHORT_WAIT, remote.recv(&mut output))
				.await
				.is_err()
		);
		route.current.set(route_binding(generation));
		assert!(matches!(peer.initiate(&mut output), Err(UdpError::Retired)));
	});
}

#[test]
fn rejects_changed_kernel_peer_before_outer_egress() {
	run(async {
		let (socket, approved) = socket_pair().await;
		let unauthorized = UdpSocket::bind(BIND_LOOPBACK).await.unwrap();
		let generation = binding(1);
		let protocol = protocol(socket.peer_addr().unwrap(), true, generation);
		let mut peer =
			UdpPeer::from_connected(MockRoute::new(generation), socket, protocol).unwrap();
		peer.active
			.as_ref()
			.unwrap()
			.socket
			.connect(unauthorized.local_addr().unwrap())
			.await
			.unwrap();

		let mut output = [0; MAX_DATAGRAM_BYTES];
		assert!(matches!(
			peer.initiate(&mut output),
			Err(UdpError::EndpointMismatch)
		));
		assert!(matches!(peer.initiate(&mut output), Err(UdpError::Retired)));
		for destination in [&approved, &unauthorized] {
			assert!(
				tokio::time::timeout(SHORT_WAIT, destination.recv(&mut output))
					.await
					.is_err()
			);
		}
	});
}

#[test]
fn revocation_after_entering_receive_wait_retires_before_ingress() {
	run(async {
		let (route, mut actor, _) = peers().await;
		let mut output = [0; MAX_DATAGRAM_BYTES];
		{
			let mut receive = std::pin::pin!(actor.receive_one(SHORT_WAIT, &mut output));
			std::future::poll_fn(|context| {
				assert!(receive.as_mut().poll(context).is_pending());
				std::task::Poll::Ready(())
			})
			.await;
			route.current.set(RouteObservation::Unavailable);
			assert!(matches!(receive.await, Err(UdpError::RouteChanged)));
		}
		assert!(matches!(
			actor.initiate(&mut output),
			Err(UdpError::Retired)
		));
	});
}

#[test]
fn expired_peer_retires_and_old_generation_cannot_reopen() {
	run(async {
		let (route, mut peer, _) = peers().await;
		peer.active.as_mut().unwrap().protocol.expire_for_test();
		let mut output = [0; MAX_DATAGRAM_BYTES];
		assert!(matches!(
			peer.tick(&mut output),
			Err(UdpError::Protocol(ProtocolError::Expired))
		));
		assert!(matches!(peer.initiate(&mut output), Err(UdpError::Retired)));

		let (socket, _) = socket_pair().await;
		let repeated = protocol(socket.peer_addr().unwrap(), true, binding(1));
		assert!(matches!(
			UdpPeer::from_connected(route.clone(), socket, repeated),
			Err(UdpError::GenerationUnavailable)
		));

		route.current.set(route_binding(binding(2)));
		let (socket, _) = socket_pair().await;
		let wrong = protocol(socket.peer_addr().unwrap(), true, binding(1));
		assert!(matches!(
			UdpPeer::from_connected(route.clone(), socket, wrong),
			Err(UdpError::RouteChanged)
		));
		let (socket, _) = socket_pair().await;
		let next = protocol(socket.peer_addr().unwrap(), true, binding(2));
		assert!(UdpPeer::from_connected(route, socket, next).is_ok());
	});
}

struct MockConnector {
	route: MockRoute,
	pending: Option<EmbeddedDialCommand>,
}

impl EmbeddedDialConnector for MockConnector {
	type Pending = ();
	type Error = io::Error;

	fn observation(&self) -> RouteObservation {
		self.route.current.get()
	}

	fn enqueue(&mut self, command: EmbeddedDialCommand) -> Result<(), io::Error> {
		if self.pending.is_some() {
			return Err(io::Error::from(io::ErrorKind::WouldBlock));
		}
		self.pending = Some(command);
		Ok(())
	}
}

#[test]
fn admits_one_exact_dispatched_dial_and_refuses_queued_command_after_route_loss() {
	run(async {
		let (route, mut actor, mut remote) = peers().await;
		let generation = binding(1);
		let requested =
			InnerDial::new(InnerDialKind::Stream, SocketAddr::from((REMOTE, 22))).unwrap();
		let wrong_purpose =
			InnerDial::new(InnerDialKind::DnsUdp, SocketAddr::from((REMOTE, 53))).unwrap();
		let wrong_peer =
			InnerDial::new(InnerDialKind::Stream, SocketAddr::from((LOCAL, 22))).unwrap();
		let targets = [requested, wrong_purpose, wrong_peer];
		let policy =
			WireGuardDialPolicy::new(ProfileRevision::from_bytes(generation.revision), &targets)
				.unwrap();
		let session = WireGuardDialSession::bind(
			&policy,
			generation.actor,
			generation.generation,
			route.current.get(),
		)
		.unwrap();
		let mut connector = MockConnector {
			route: route.clone(),
			pending: None,
		};
		handshake(&mut actor, &mut remote).await;
		for unsupported in [wrong_purpose, wrong_peer] {
			let permit = session.authorize(unsupported, route.current.get()).unwrap();
			session.dispatch(permit, &mut connector).unwrap();
			assert!(matches!(
				actor.admit_inner_dial(connector.pending.take().unwrap()),
				Err(UdpError::InnerTargetUnsupported)
			));
		}
		for revoke in [false, true] {
			let permit = session.authorize(requested, route.current.get()).unwrap();
			session.dispatch(permit, &mut connector).unwrap();
			if revoke {
				route.current.set(RouteObservation::Direct);
			}
			let result = actor.admit_inner_dial(connector.pending.take().unwrap());
			if revoke {
				assert!(matches!(result, Err(UdpError::RouteChanged)));
			} else {
				assert!(matches!(result, Ok(target) if target == requested));
			}
		}
		assert!(actor.active.is_none());
	});
}
