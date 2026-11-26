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

fn handshake(client: &mut HarnessPeer, server: &mut HarnessPeer, rekey: bool) {
	let mut first = [0; MAX_DATAGRAM_BYTES];
	let mut second = [0; MAX_DATAGRAM_BYTES];
	let initiation = if rekey {
		client.wg.tick(&mut first).unwrap()
	} else {
		client.wg.initiate(&mut first).unwrap()
	};
	client.wg.check_output(&initiation).unwrap();
	let initiation = datagram(initiation, server.outer);
	let response = server
		.wg
		.receive(client.outer, initiation, &mut second)
		.unwrap();
	server.wg.check_output(&response).unwrap();
	let response = datagram(response, client.outer);
	let confirmation = client
		.wg
		.receive(server.outer, response, &mut first)
		.unwrap();
	client.wg.check_output(&confirmation).unwrap();
	let confirmation = datagram(confirmation, server.outer);
	let result = server
		.wg
		.receive(client.outer, confirmation, &mut second)
		.unwrap();
	server.wg.check_output(&result).unwrap();
	assert!(matches!(result, PacketOutput::None));
}

fn push(sender: &mut HarnessPeer, receiver: &mut HarnessPeer) {
	sender
		.tcp
		.egress(|_, packet| {
			let mut encrypted = [0; MAX_DATAGRAM_BYTES];
			let mut decrypted = [0; MAX_DATAGRAM_BYTES];
			let output = sender.wg.send(packet, &mut encrypted).unwrap();
			sender.wg.check_output(&output).unwrap();
			let ciphertext = datagram(output, receiver.outer);
			assert_ne!(packet, ciphertext);
			let input = receiver
				.wg
				.receive(sender.outer, ciphertext, &mut decrypted)
				.unwrap();
			receiver.wg.check_output(&input).unwrap();
			let PacketOutput::Inner(bytes) = input else {
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
fn the_same_tcp_flow_exchanges_data_beyond_its_original_wireguard_keys() {
	for route in [ipv4_flow(), ipv6_flow()] {
		let (mut client, mut server) = two_peers(route);
		handshake(&mut client, &mut server, false);
		let initial = [
			client.wg.selected_key_for_test(),
			server.wg.selected_key_for_test(),
		];
		let bindings = [client.tcp.binding(), server.tcp.binding()];
		let source: Vec<_> = (0..STREAM_BUFFER_BYTES + 137)
			.map(|index| (index % 251) as u8)
			.collect();
		let mut rolled = false;
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
			if !rolled && !received.is_empty() {
				assert!(received.len() < source.len());
				let step = Duration::from_secs(61);
				client.wg.advance_rekey_clock_for_test(step);
				server.wg.advance_rekey_clock_for_test(step);
				handshake(&mut client, &mut server, true);
				assert_ne!(client.wg.selected_key_for_test(), initial[0]);
				assert_ne!(server.wg.selected_key_for_test(), initial[1]);
				client.wg.advance_rekey_clock_for_test(step);
				server.wg.advance_rekey_clock_for_test(step);
				rolled = true;
			}
			if received.len() == source.len() {
				break;
			}
		}
		assert!(rolled);
		assert!(client.tcp.binding() == bindings[0] && server.tcp.binding() == bindings[1]);
		assert_eq!(received, source);
	}
}
