use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use exacopy_endpoint::wireguard::{
	EmbeddedDialConnector, InnerDial, InnerDialKind, ProfileRevision, WireGuardDialPolicy,
	WireGuardDialSession,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::protocol::{INNER_MTU, PeerBinding, PublicKey, StaticSecret};
use crate::stack::{PacketDisposition, PacketEvent, PacketInterest, PacketIo, TcpState};
use crate::udp::route_binding;
use crate::udp::tests::{
	LOCAL, REMOTE, binding, fixture_ip, handshake, protocol, run, socket_pair,
};

use super::*;

#[derive(Clone)]
pub(super) struct Owner(Arc<Mutex<Lease>>);

struct Lease {
	binding: RouteObservation,
	revocation: RouteRevocation,
	claimed: bool,
}

impl Owner {
	fn new(binding: PeerBinding) -> Self {
		Self(Arc::new(Mutex::new(Lease {
			binding: route_binding(binding),
			revocation: RouteRevocation::new(binding),
			claimed: false,
		})))
	}

	fn revoke(&self) {
		let mut lease = self.0.lock().unwrap();
		lease.binding = RouteObservation::Unavailable;
		lease.revocation.revoke();
	}
}

impl RouteOwner for Owner {
	fn with_observation<T>(&self, observe: impl FnOnce(RouteObservation) -> T) -> T {
		let lease = self.0.lock().unwrap();
		observe(lease.binding)
	}

	fn claim_generation(&self, binding: RouteObservation) -> bool {
		let mut lease = self.0.lock().unwrap();
		if lease.claimed || binding != lease.binding {
			return false;
		}
		lease.claimed = true;
		true
	}
}

impl TcpRouteOwner for Owner {
	fn stream_revocation(&self, binding: RouteObservation) -> Option<RouteRevocation> {
		let lease = self.0.lock().unwrap();
		(lease.claimed && lease.binding == binding).then(|| lease.revocation.clone())
	}
}

pub(super) async fn pair() -> (Owner, UdpPeer<Owner>, Owner, UdpPeer<Owner>) {
	let (first, second) = socket_pair().await;
	let first_owner = Owner::new(binding(1));
	let second_owner = Owner::new(binding(2));
	let first_protocol = protocol(first.peer_addr().unwrap(), true, binding(1));
	let second_protocol = protocol(second.peer_addr().unwrap(), false, binding(2));
	let mut first = UdpPeer::from_connected(first_owner.clone(), first, first_protocol).unwrap();
	let mut second =
		UdpPeer::from_connected(second_owner.clone(), second, second_protocol).unwrap();
	handshake(&mut first, &mut second).await;
	(first_owner, first, second_owner, second)
}

#[test]
fn accepted_means_the_exact_inner_packet_reached_connected_udp() {
	run(async {
		let (owner, first, _, second) = pair().await;
		let mut first = UdpPacketIo::new(first, binding(1)).unwrap();
		let mut second = UdpPacketIo::new(second, binding(2)).unwrap();
		let payload = fixture_ip(LOCAL, REMOTE);
		let mut packet = [0; INNER_MTU];
		assert_eq!(
			first.send(binding(1), &payload).unwrap(),
			PacketDisposition::Backpressure
		);
		assert!(matches!(
			first
				.wait(
					PacketInterest {
						receive: false,
						writable: true
					},
					&mut packet
				)
				.await
				.unwrap(),
			PacketEvent::Writable
		));
		assert_eq!(
			first.send(binding(1), &payload).unwrap(),
			PacketDisposition::Accepted
		);
		assert!(matches!(
			tokio::time::timeout(
				Duration::from_secs(2),
				second.wait(
					PacketInterest {
						receive: true,
						writable: false
					},
					&mut packet
				),
			)
			.await
			.unwrap()
			.unwrap(),
			PacketEvent::Received(count) if count == payload.len()
		));
		assert_eq!(&packet[..payload.len()], &payload);
		owner.revoke();
		assert!(matches!(
			first.send(binding(1), &payload),
			Err(UdpTcpError::Udp(UdpError::RouteChanged))
		));
	});
}

struct Connector<'a>(&'a Owner, Option<EmbeddedDialCommand>);

impl EmbeddedDialConnector for Connector<'_> {
	type Pending = ();
	type Error = std::convert::Infallible;

	fn observation(&self) -> RouteObservation {
		self.0.with_observation(|value| value)
	}

	fn enqueue(&mut self, command: EmbeddedDialCommand) -> Result<(), Self::Error> {
		assert!(self.1.replace(command).is_none());
		Ok(())
	}
}

fn approved_dial(owner: &Owner, binding: PeerBinding, target: SocketAddr) -> EmbeddedDialCommand {
	let dial = InnerDial::new(InnerDialKind::Stream, target).unwrap();
	let targets = [dial];
	let policy =
		WireGuardDialPolicy::new(ProfileRevision::from_bytes(binding.revision), &targets).unwrap();
	let mut connector = Connector(owner, None);
	let current = connector.observation();
	let session =
		WireGuardDialSession::bind(&policy, binding.actor, binding.generation, current).unwrap();
	let permit = session.authorize(dial, current).unwrap();
	session.dispatch(permit, &mut connector).unwrap();
	connector.1.unwrap()
}

const CLIENT_PORT: NonZeroU16 = NonZeroU16::new(49_152).unwrap();
const SERVER_PORT: u16 = 22;
const MTU: u16 = 1500;

fn settings() -> TcpDialSettings {
	TcpDialSettings {
		local_port: CLIENT_PORT,
		outer_path_mtu: MTU,
		random_seed: 1,
	}
}

fn client(owner: &Owner, peer: UdpPeer<Owner>) -> UdpTcpAdmission<Owner> {
	let dial = approved_dial(owner, binding(1), SocketAddr::from((REMOTE, SERVER_PORT)));
	peer.into_tcp(dial, settings()).unwrap()
}

fn passive(
	server_owner: &Owner,
	second: UdpPeer<Owner>,
) -> (InnerTcpStream, TcpPump, UdpPacketIo<Owner>) {
	let outer = second.active.as_ref().unwrap().protocol.outer_endpoint();
	let server_binding = binding(2);
	let flow = TcpFlow {
		binding: server_binding,
		local: SocketAddr::from((REMOTE, SERVER_PORT)),
		remote: SocketAddr::from((LOCAL, CLIENT_PORT.get())),
		mtu: InnerMtu::from_outer(outer, MTU).unwrap(),
	};
	let server_tcp = crate::stack::tests::passive(flow);
	assert_eq!(server_tcp.state(), TcpState::Opening);
	let (server, pump) = server_tcp
		.into_async(
			server_owner
				.stream_revocation(route_binding(server_binding))
				.unwrap(),
		)
		.unwrap();
	let packets = UdpPacketIo::new(second, server_binding).unwrap();
	(server, pump, packets)
}

#[test]
fn session_readiness_follows_the_connected_provider_without_claiming_the_dial() {
	run(async {
		let (first, second) = socket_pair().await;
		let owner = Owner::new(binding(1));
		let first_protocol = protocol(first.peer_addr().unwrap(), true, binding(1));
		let second_protocol = protocol(second.peer_addr().unwrap(), false, binding(2));
		let mut first = UdpPeer::from_connected(owner.clone(), first, first_protocol).unwrap();
		let mut second =
			UdpPeer::from_connected(Owner::new(binding(2)), second, second_protocol).unwrap();
		assert!(!first.session_ready().unwrap());
		assert!(!second.session_ready().unwrap());
		handshake(&mut first, &mut second).await;
		assert!(first.session_ready().unwrap());
		assert!(first.session_ready().unwrap());
		assert!(second.session_ready().unwrap());
		drop(client(&owner, first));
	});
}

#[test]
fn another_generation_cannot_supply_the_command_for_this_transport() {
	run(async {
		let (_, first, _, _) = pair().await;
		let another = Owner::new(binding(3));
		let dial = approved_dial(
			&another,
			binding(3),
			SocketAddr::from((REMOTE, SERVER_PORT)),
		);
		assert!(matches!(
			first.into_tcp(dial, settings()),
			Err(UdpTcpError::Udp(UdpError::Dial(_)))
		));
	});
}

#[test]
fn owner_revocation_reaches_stream_before_the_first_driver_poll() {
	run(async {
		let (owner, first, _, _) = pair().await;
		client(&owner, first)
			.with_stream(async |mut stream, driver, route| {
				assert!(route.current().is_none());
				owner.revoke();
				assert!(route.current().is_none());
				assert!(stream.write_all(b"fixture").await.is_err());
				assert!(driver.run().await.is_err());
			})
			.await;
	});
}

#[test]
fn streams_bytes_both_directions_over_native_udp_and_inner_tcp() {
	run(async {
		let (owner, first, server_owner, second) = pair().await;
		let (mut server, server_pump, server_packets) = passive(&server_owner, second);
		client(&owner, first)
			.with_stream(async |mut client, driver, route| {
				assert!(route.current().is_none());
				let client_driver = tokio::spawn(driver.run());
				let server_driver = tokio::spawn(server_pump.run(server_packets));
				tokio::time::timeout(Duration::from_secs(5), async {
					let request = vec![17; 128 * 1024];
					let response = vec![91; 192 * 1024];
					let put = async {
						client.write_all(&request).await.unwrap();
						let mut received = vec![0; response.len()];
						client.read_exact(&mut received).await.unwrap();
						assert_eq!(received, response);
					};
					let get = async {
						let mut received = vec![0; request.len()];
						server.read_exact(&mut received).await.unwrap();
						assert_eq!(received, request);
						server.write_all(&response).await.unwrap();
					};
					tokio::join!(put, get);
				})
				.await
				.unwrap();
				let observed = route.current().unwrap();
				assert!(observed.binding() == binding(1));
				assert_eq!(observed.inner(), SocketAddr::from((REMOTE, SERVER_PORT)));
				assert_eq!(
					observed.remote_public_key(),
					PublicKey::from(&StaticSecret::from([123; 32])).to_bytes(),
				);
				owner.revoke();
				assert!(route.current().is_none());
				server_owner.revoke();
				assert!(client_driver.await.unwrap().is_err());
				assert!(server_driver.await.unwrap().is_err());
			})
			.await;
	});
}

#[test]
fn live_observation_refuses_lease_replacement_and_dropped_flow_resources() {
	run(async {
		for outcome in [Retire::Driver, Retire::Stream, Retire::Lease] {
			let (owner, first, server_owner, second) = pair().await;
			let (mut server, server_pump, server_packets) = passive(&server_owner, second);
			client(&owner, first)
				.with_stream(async |mut stream, driver, route| {
					let client_driver = tokio::spawn(driver.run());
					let server_driver = tokio::spawn(server_pump.run(server_packets));
					tokio::time::timeout(Duration::from_secs(2), async {
						stream.write_u8(17).await.unwrap();
						assert_eq!(server.read_u8().await.unwrap(), 17);
						server.write_u8(42).await.unwrap();
						assert_eq!(stream.read_u8().await.unwrap(), 42);
					})
					.await
					.unwrap();
					assert!(route.current().is_some());
					match outcome {
						Retire::Driver => {
							client_driver.abort();
							assert!(client_driver.await.unwrap_err().is_cancelled());
							assert!(stream.write_u8(1).await.is_err());
							assert!(route.current().is_none());
						}
						Retire::Stream => {
							drop(stream);
							assert!(route.current().is_none());
							assert!(client_driver.await.unwrap().is_err());
						}
						Retire::Lease => {
							// Even a delayed notification cannot preserve the old authority.
							owner.0.lock().unwrap().binding = route_binding(binding(3));
							assert!(route.current().is_none());
							owner.revoke();
							assert!(client_driver.await.unwrap().is_err());
						}
					}
					server_owner.revoke();
					assert!(server_driver.await.unwrap().is_err());
				})
				.await;
		}
	});
}

enum Retire {
	Driver,
	Stream,
	Lease,
}
