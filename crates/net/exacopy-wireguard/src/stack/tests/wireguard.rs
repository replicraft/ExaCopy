use crate::protocol::{
	MAX_DATAGRAM_BYTES, PacketOutput, PeerAddresses, ProtocolPeer, PublicKey, StaticSecret,
};

use super::*;

struct HarnessPeer {
	tcp: InnerTcp,
	wg: ProtocolPeer,
	outer: SocketAddr,
}

fn make_wg(tcp: &InnerTcp, outer: SocketAddr, keys: (StaticSecret, PublicKey)) -> ProtocolPeer {
	ProtocolPeer::new(
		tcp.binding(),
		PeerAddresses {
			outer,
			local: tcp.flow.local.ip(),
			remote: tcp.flow.remote.ip(),
		},
		keys.0,
		keys.1,
	)
	.unwrap()
}

fn two_peers(route: TcpFlow) -> (HarnessPeer, HarnessPeer) {
	let (client, server) = pair(route);
	let client_outer = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 51820));
	let server_outer = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 11), 51820));
	let client_secret = StaticSecret::from([41; 32]);
	let server_secret = StaticSecret::from([53; 32]);
	let client_public = PublicKey::from(&client_secret);
	let server_public = PublicKey::from(&server_secret);

	let client_wg = make_wg(&client, server_outer, (client_secret, server_public));
	let server_wg = make_wg(&server, client_outer, (server_secret, client_public));
	(
		HarnessPeer {
			tcp: client,
			wg: client_wg,
			outer: client_outer,
		},
		HarnessPeer {
			tcp: server,
			wg: server_wg,
			outer: server_outer,
		},
	)
}

fn datagram(output: PacketOutput<'_>, expected: SocketAddr) -> &[u8] {
	let PacketOutput::Outer { destination, bytes } = output else {
		panic!("expected an outer datagram");
	};
	assert_eq!(destination, expected);
	bytes
}

fn handshake(client: &mut HarnessPeer, server: &mut HarnessPeer) {
	let mut first = [0; MAX_DATAGRAM_BYTES];
	let mut second = [0; MAX_DATAGRAM_BYTES];
	let initiation = datagram(client.wg.initiate(&mut first).unwrap(), server.outer);
	let response = datagram(
		server
			.wg
			.receive(client.outer, initiation, &mut second)
			.unwrap(),
		client.outer,
	);
	let confirmation = datagram(
		client
			.wg
			.receive(server.outer, response, &mut first)
			.unwrap(),
		server.outer,
	);
	assert!(matches!(
		server
			.wg
			.receive(client.outer, confirmation, &mut second)
			.unwrap(),
		PacketOutput::None
	));
}

fn push(sender: &mut HarnessPeer, receiver: &mut HarnessPeer) {
	sender
		.tcp
		.egress(|_, packet| {
			let mut encrypted = [0; MAX_DATAGRAM_BYTES];
			let mut decrypted = [0; MAX_DATAGRAM_BYTES];
			let ciphertext = datagram(
				sender.wg.send(packet, &mut encrypted).unwrap(),
				receiver.outer,
			);
			assert_ne!(packet, ciphertext);
			let PacketOutput::Inner(bytes) = receiver
				.wg
				.receive(sender.outer, ciphertext, &mut decrypted)
				.unwrap()
			else {
				panic!("expected an authenticated TCP packet");
			};
			receiver
				.tcp
				.ingress(bytes)
				.map(|()| PacketDisposition::Accepted)
		})
		.unwrap();
}

#[test]
fn a_tcp_flow_exchanges_data_through_two_in_memory_wireguard_peers() {
	for route in [ipv4_flow(), ipv6_flow()] {
		let (mut client, mut server) = two_peers(route);
		handshake(&mut client, &mut server);

		let source = vec![53; STREAM_BUFFER_BYTES + 137];
		let mut transmitted = 0;
		let mut received = Vec::new();
		for now in 0..2_000 {
			let now = Duration::from_millis(now);
			client.tcp.poll(now).unwrap();
			server.tcp.poll(now).unwrap();
			push(&mut client, &mut server);
			push(&mut server, &mut client);
			write_all(&mut client.tcp, &source, &mut transmitted);
			read_available(&mut server.tcp, &mut received);
			if received.len() == source.len() {
				break;
			}
		}
		assert_eq!(received, source);
	}
}
