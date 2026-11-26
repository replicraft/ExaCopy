use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

const ACTOR: NonZeroU128 = NonZeroU128::MIN;
const GENERATION: NonZeroU64 = NonZeroU64::MIN;
const A: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 2);
const OTHER: Ipv4Addr = Ipv4Addr::new(10, 10, 0, 3);
const A6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
const B6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

fn endpoint(port: u16) -> SocketAddr {
	SocketAddr::from(([192, 0, 2, 1], port))
}

fn binding(revision: u8) -> PeerBinding {
	PeerBinding {
		revision: [revision; 32],
		actor: ACTOR,
		generation: GENERATION,
	}
}

fn peers(a: IpAddr, b: IpAddr, a_remote: IpAddr) -> (ProtocolPeer, ProtocolPeer) {
	// Only fixture static identities. BoringTun generates handshake ephemeral keys.
	let a_secret = StaticSecret::from([113; 32]);
	let b_secret = StaticSecret::from([127; 32]);
	let a_key = PublicKey::from(&a_secret);
	let b_key = PublicKey::from(&b_secret);
	let client = ProtocolPeer::new(
		binding(1),
		PeerAddresses {
			outer: endpoint(20001),
			local: a,
			remote: a_remote,
		},
		a_secret,
		b_key,
	)
	.unwrap();
	let server = ProtocolPeer::new(
		binding(2),
		PeerAddresses {
			outer: endpoint(20000),
			local: b,
			remote: a,
		},
		b_secret,
		a_key,
	)
	.unwrap();
	(client, server)
}

fn outer(result: PacketOutput<'_>, destination: SocketAddr) -> &[u8] {
	let PacketOutput::Outer {
		destination: actual,
		bytes,
	} = result
	else {
		panic!("expected a WireGuard datagram");
	};
	assert_eq!(actual, destination);
	bytes
}

fn handshake(client: &mut ProtocolPeer, server: &mut ProtocolPeer) {
	let mut to_server = [0; MAX_DATAGRAM_BYTES];
	let mut to_client = [0; MAX_DATAGRAM_BYTES];
	let initiation = outer(client.initiate(&mut to_server).unwrap(), endpoint(20001));
	let response = outer(
		server
			.receive(endpoint(20000), initiation, &mut to_client)
			.unwrap(),
		endpoint(20000),
	);
	let keepalive = outer(
		client
			.receive(endpoint(20001), response, &mut to_server)
			.unwrap(),
		endpoint(20001),
	);
	assert!(matches!(
		server
			.receive(endpoint(20000), keepalive, &mut to_client)
			.unwrap(),
		PacketOutput::None
	));
	assert!(client.observation().has_session && server.observation().has_session);
	assert!(client.observation().binding == binding(1));
	assert!(server.observation().binding == binding(2));
}

fn ipv4(source: Ipv4Addr, destination: Ipv4Addr) -> [u8; 24] {
	let mut packet = [0; 24];
	packet[0] = 0x45;
	packet[2..4].copy_from_slice(&24_u16.to_be_bytes());
	packet[12..16].copy_from_slice(&source.octets());
	packet[16..20].copy_from_slice(&destination.octets());
	packet[20..].copy_from_slice(b"test");
	packet
}

fn ipv6(source: Ipv6Addr, destination: Ipv6Addr) -> [u8; 44] {
	let mut packet = [0; 44];
	packet[0] = 0x60;
	packet[4..6].copy_from_slice(&4_u16.to_be_bytes());
	packet[8..24].copy_from_slice(&source.octets());
	packet[24..40].copy_from_slice(&destination.octets());
	packet[40..].copy_from_slice(b"test");
	packet
}

#[test]
fn actual_boringtun_handshake_and_encryption_round_trip_both_families() {
	for (a, b, packet) in [
		(A.into(), B.into(), ipv4(A, B).to_vec()),
		(A6.into(), B6.into(), ipv6(A6, B6).to_vec()),
	] {
		let (mut client, mut server) = peers(a, b, b);
		let mut encrypted = [0; MAX_DATAGRAM_BYTES];
		let mut decrypted = [0; MAX_DATAGRAM_BYTES];
		assert!(!client.observation().has_session);
		assert_eq!(
			client.send(&packet, &mut encrypted).err(),
			Some(ProtocolError::NoSession)
		);
		handshake(&mut client, &mut server);
		let datagram = outer(
			client.send(&packet, &mut encrypted).unwrap(),
			endpoint(20001),
		);
		assert!(
			!datagram
				.windows(packet.len())
				.any(|window| window == packet.as_slice())
		);
		let PacketOutput::Inner(received) = server
			.receive(endpoint(20000), datagram, &mut decrypted)
			.unwrap()
		else {
			panic!("expected an authenticated inner packet");
		};
		assert_eq!(received, packet);
		assert_eq!(
			server
				.receive(endpoint(20000), datagram, &mut decrypted)
				.err(),
			Some(ProtocolError::Rejected)
		);
	}
}

#[test]
fn refuses_foreign_endpoint_corrupted_ciphertext_and_unapproved_ip() {
	let (mut client, mut server) = peers(A.into(), B.into(), OTHER.into());
	handshake(&mut client, &mut server);
	let mut encrypted = [0; MAX_DATAGRAM_BYTES];
	let mut decrypted = [0; MAX_DATAGRAM_BYTES];
	assert_eq!(
		client.send(&ipv4(A, B), &mut encrypted).err(),
		Some(ProtocolError::InnerScope)
	);
	let datagram = outer(
		client.send(&ipv4(A, OTHER), &mut encrypted).unwrap(),
		endpoint(20001),
	);
	assert_eq!(
		server
			.receive(endpoint(20002), datagram, &mut decrypted)
			.err(),
		Some(ProtocolError::OuterEndpoint)
	);
	let mut corrupted = datagram.to_vec();
	*corrupted.last_mut().unwrap() ^= 1;
	assert_eq!(
		server
			.receive(endpoint(20000), &corrupted, &mut decrypted)
			.err(),
		Some(ProtocolError::Rejected)
	);
	assert_eq!(
		server
			.receive(endpoint(20000), datagram, &mut decrypted)
			.err(),
		Some(ProtocolError::InnerScope)
	);
}

#[test]
fn refuses_degenerate_configuration_and_bounds_before_protocol_call() {
	let addresses = PeerAddresses {
		outer: endpoint(20001),
		local: A.into(),
		remote: B.into(),
	};
	assert_eq!(
		ProtocolPeer::new(
			binding(1),
			addresses,
			StaticSecret::from([113; 32]),
			PublicKey::from([0; 32])
		)
		.err(),
		Some(ProtocolError::InvalidPeerKey)
	);
	assert_eq!(
		ProtocolPeer::new(
			binding(1),
			addresses,
			StaticSecret::from([0; 32]),
			PublicKey::from(&StaticSecret::from([127; 32]))
		)
		.err(),
		Some(ProtocolError::InvalidPeerKey)
	);

	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	let mut output = [0; MAX_DATAGRAM_BYTES];
	assert_eq!(
		client.send(&[0; INNER_MTU + 1], &mut output).err(),
		Some(ProtocolError::PacketBounds)
	);
	assert_eq!(
		client.send(&ipv4(A, B)[..20], &mut output).err(),
		Some(ProtocolError::InvalidInnerPacket)
	);
	assert_eq!(
		server.receive(endpoint(20000), &[], &mut output).err(),
		Some(ProtocolError::PacketBounds)
	);
	assert_eq!(
		server
			.receive(endpoint(20000), &[0; MAX_DATAGRAM_BYTES + 1], &mut output)
			.err(),
		Some(ProtocolError::PacketBounds)
	);
}

#[test]
fn transport_counter_boundary_and_truncated_header_are_refused_before_boringtun() {
	use packet::REJECT_AFTER_MESSAGES;

	let mut header = [0; 16];
	header[..4].copy_from_slice(&4_u32.to_le_bytes());
	header[8..].copy_from_slice(&(REJECT_AFTER_MESSAGES - 1).to_le_bytes());
	assert!(admitted_counter(&header));
	assert!(!admitted_counter(&header[..15]));
	header[8..].copy_from_slice(&REJECT_AFTER_MESSAGES.to_le_bytes());
	assert!(!admitted_counter(&header));

	let (_, mut server) = peers(A.into(), B.into(), B.into());
	let mut output = [0; MAX_DATAGRAM_BYTES];
	assert_eq!(
		server.receive(endpoint(20000), &header, &mut output).err(),
		Some(ProtocolError::CounterLimit)
	);
	assert_eq!(server.operations_remaining, MAX_GENERATION_OPERATIONS);
}

#[test]
fn generation_age_and_budget_gate_data_and_control_operations() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	let mut wire = [0; MAX_DATAGRAM_BYTES];
	let mut output = [0; MAX_DATAGRAM_BYTES];

	client.operations_remaining = 1;
	let datagram = outer(
		client.send(&ipv4(A, B), &mut wire).unwrap(),
		endpoint(20001),
	);
	assert!(!client.observation().has_session);
	assert_eq!(
		client.send(&ipv4(A, B), &mut output).err(),
		Some(ProtocolError::OperationLimit)
	);
	assert_eq!(
		client.tick(&mut output).err(),
		Some(ProtocolError::OperationLimit)
	);

	server.clock.expire_for_test();
	assert!(!server.observation().has_session);
	assert_eq!(
		server.receive(endpoint(20000), datagram, &mut output).err(),
		Some(ProtocolError::Expired)
	);
	assert_eq!(
		server.initiate(&mut output).err(),
		Some(ProtocolError::Expired)
	);
	assert_eq!(server.tick(&mut output).err(), Some(ProtocolError::Expired));
}

// Public low-order coordinate fixtures from libsodium 1.0.20's ref10 X25519
// implementation. The guard uses the library DH result, never this test set.
const TORSION_COORDINATES: [[u8; 32]; 7] = [
	[0; 32],
	boundary_coordinate(1, 0),
	[
		0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
		0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
		0xb8, 0x00,
	],
	[
		0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
		0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
		0x11, 0x57,
	],
	boundary_coordinate(0xec, 0xff),
	boundary_coordinate(0xed, 0xff),
	boundary_coordinate(0xee, 0xff),
];

const fn boundary_coordinate(first: u8, fill: u8) -> [u8; 32] {
	let mut coordinate = [fill; 32];
	coordinate[0] = first;
	coordinate[31] &= 0x7f;
	coordinate
}

fn handshake_header<const N: usize>(
	message_type: u32,
	ephemeral_offset: usize,
	coordinate: [u8; 32],
) -> [u8; N] {
	let mut wire = [0; N];
	wire[..4].copy_from_slice(&message_type.to_le_bytes());
	wire[ephemeral_offset..][..32].copy_from_slice(&coordinate);
	wire
}

#[test]
fn refuses_low_order_ephemerals_and_high_bit_aliases_in_both_handshake_shapes() {
	let (_, mut server) = peers(A.into(), B.into(), B.into());
	for mut coordinate in TORSION_COORDINATES {
		for last_bit in [0, 0x80] {
			coordinate[31] = (coordinate[31] & 0x7f) | last_bit;
			let initiation = handshake_header::<148>(1, 8, coordinate);
			let response = handshake_header::<92>(2, 12, coordinate);
			for wire in [initiation.as_slice(), response.as_slice()] {
				let mut output = [0x55; MAX_DATAGRAM_BYTES];
				assert_eq!(
					server.receive(endpoint(20000), wire, &mut output).err(),
					Some(ProtocolError::NonContributoryEphemeral)
				);
				assert_eq!(output, [0x55; MAX_DATAGRAM_BYTES]);
			}
		}
	}
	assert_eq!(server.handshakes_remaining, MAX_INCOMING_HANDSHAKES - 28);
	assert!(!server.observation().has_session);
}

#[test]
fn malformed_and_foreign_frames_do_not_charge_expensive_handshake_allowance() {
	let (_, mut server) = peers(A.into(), B.into(), B.into());
	let wire = handshake_header::<148>(1, 8, [0; 32]);
	let mut output = [0; MAX_DATAGRAM_BYTES];
	assert_eq!(
		server.receive(endpoint(20001), &wire, &mut output).err(),
		Some(ProtocolError::OuterEndpoint)
	);
	assert_eq!(
		server
			.receive(endpoint(20000), &wire[..147], &mut output)
			.err(),
		Some(ProtocolError::Rejected)
	);
	let mut reserved_bit_set = wire;
	reserved_bit_set[1] = 1;
	assert_eq!(
		server
			.receive(endpoint(20000), &reserved_bit_set, &mut output)
			.err(),
		Some(ProtocolError::Rejected)
	);
	assert_eq!(server.handshakes_remaining, MAX_INCOMING_HANDSHAKES);
}

#[test]
fn handshake_budget_exhaustion_preserves_an_established_data_session() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	assert_eq!(server.handshakes_remaining, MAX_INCOMING_HANDSHAKES - 1);
	assert_eq!(client.handshakes_remaining, MAX_INCOMING_HANDSHAKES - 1);
	server.handshakes_remaining = 1;
	let wire = handshake_header::<148>(1, 8, [0; 32]);
	let mut server_output = [0; MAX_DATAGRAM_BYTES];
	assert_eq!(
		server
			.receive(endpoint(20000), &wire, &mut server_output)
			.err(),
		Some(ProtocolError::NonContributoryEphemeral)
	);
	let operations_remaining = server.operations_remaining;
	assert_eq!(
		server
			.receive(endpoint(20000), &wire, &mut server_output)
			.err(),
		Some(ProtocolError::HandshakeLimit)
	);
	assert_eq!(server.operations_remaining, operations_remaining);
	assert!(server.observation().has_session);

	let packet = ipv4(A, B);
	let mut client_output = [0; MAX_DATAGRAM_BYTES];
	let ciphertext = outer(
		client.send(&packet, &mut client_output).unwrap(),
		endpoint(20001),
	);
	assert!(matches!(
		server.receive(endpoint(20000), ciphertext, &mut server_output),
		Ok(PacketOutput::Inner(bytes)) if bytes == packet
	));

	server.clock.expire_for_test();
	assert_eq!(
		server
			.receive(endpoint(20000), &wire, &mut server_output)
			.err(),
		Some(ProtocolError::Expired)
	);
}

#[test]
fn expired_peer_does_not_charge_ephemeral_probe_budget() {
	let (_, mut server) = peers(A.into(), B.into(), B.into());
	server.clock.expire_for_test();
	let wire = handshake_header::<148>(1, 8, [0; 32]);
	let mut output = [0; MAX_DATAGRAM_BYTES];
	assert_eq!(
		server.receive(endpoint(20000), &wire, &mut output).err(),
		Some(ProtocolError::Expired)
	);
	assert_eq!(server.handshakes_remaining, MAX_INCOMING_HANDSHAKES);
}

mod rekey;
