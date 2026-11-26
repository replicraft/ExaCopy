use std::time::Duration;

use boringtun::noise::Packet;

use super::*;

fn advance(client: &mut ProtocolPeer, server: &mut ProtocolPeer, secs: u64) {
	client.clock.advance_for_test(Duration::from_secs(secs));
	server.clock.advance_for_test(Duration::from_secs(secs));
}

fn select_key(peer: &ProtocolPeer) -> boringtun::noise::TransportKeyId {
	peer.tunnel.current_transport_key().unwrap().id
}

fn receive_as_peer(
	recipient: &mut ProtocolPeer,
	sender_port: u16,
	datagram: &[u8],
) -> Result<bool, ProtocolError> {
	let mut output = [0; MAX_DATAGRAM_BYTES];
	recipient
		.receive(endpoint(sender_port), datagram, &mut output)
		.map(|packet| matches!(packet, PacketOutput::Inner(_)))
}

fn complete_rekey(client: &mut ProtocolPeer, server: &mut ProtocolPeer) {
	let mut initiation_buffer = [0; MAX_DATAGRAM_BYTES];
	let mut response_buffer = [0; MAX_DATAGRAM_BYTES];
	let initiation = outer(
		client.tick(&mut initiation_buffer).unwrap(),
		endpoint(20001),
	);
	assert!(matches!(
		Tunn::parse_incoming_packet(initiation),
		Ok(Packet::HandshakeInit(_))
	));
	let response = outer(
		server
			.receive(endpoint(20000), initiation, &mut response_buffer)
			.unwrap(),
		endpoint(20000),
	);
	let confirmation = outer(
		client
			.receive(endpoint(20001), response, &mut initiation_buffer)
			.unwrap(),
		endpoint(20001),
	);
	assert_eq!(receive_as_peer(server, 20000, confirmation), Ok(false));
}

#[test]
fn one_bound_peer_pair_exchanges_payload_after_original_lifetime() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	let initial_keys = [select_key(&client), select_key(&server)];
	let bindings = [client.observation().binding, server.observation().binding];
	let mut wire = [0; MAX_DATAGRAM_BYTES];
	let old_packet = outer(
		client.send(&ipv4(A, B), &mut wire).unwrap(),
		endpoint(20001),
	)
	.to_vec();
	assert_eq!(receive_as_peer(&mut server, 20000, &old_packet), Ok(true));

	advance(&mut client, &mut server, 61);
	complete_rekey(&mut client, &mut server);
	assert_ne!(select_key(&client), initial_keys[0]);
	assert_ne!(select_key(&server), initial_keys[1]);
	assert_eq!(
		receive_as_peer(&mut server, 20000, &old_packet),
		Err(ProtocolError::Rejected)
	);

	advance(&mut client, &mut server, 61);
	for (position, payload) in [b"next", b"last"].into_iter().enumerate() {
		let mut traffic = ipv4(A, B);
		traffic[20..].copy_from_slice(payload);
		let sent = outer(client.send(&traffic, &mut wire).unwrap(), endpoint(20001));
		let mut received = [0; MAX_DATAGRAM_BYTES];
		assert!(
			matches!(server.receive(endpoint(20000), sent, &mut received),
			Ok(PacketOutput::Inner(bytes)) if bytes == traffic),
			"inner record {position} must retain its bytes across rollover"
		);
	}
	let reverse = outer(
		server.send(&ipv4(B, A), &mut wire).unwrap(),
		endpoint(20000),
	);
	assert_eq!(receive_as_peer(&mut client, 20001, reverse), Ok(true));
	assert!(
		client.observation().binding == bindings[0] && server.observation().binding == bindings[1]
	);
	assert!(server.tunnel.transport_key(initial_keys[1]).is_none());
}

#[test]
fn expired_old_selection_cannot_send_or_queue_and_future_key_reselects() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	let old_selected = select_key(&server);
	let mut wire = [0; MAX_DATAGRAM_BYTES];
	let delayed = outer(
		client.send(&ipv4(A, B), &mut wire).unwrap(),
		endpoint(20001),
	)
	.to_vec();
	let expired = outer(
		client.send(&ipv4(A, B), &mut wire).unwrap(),
		endpoint(20001),
	)
	.to_vec();

	advance(&mut client, &mut server, 61);
	complete_rekey(&mut client, &mut server);
	let new = select_key(&server);
	assert_eq!(receive_as_peer(&mut server, 20000, &delayed), Ok(true));
	assert_eq!(select_key(&server), old_selected);

	advance(&mut client, &mut server, 60);
	assert_eq!(
		server.send(&ipv4(B, A), &mut wire).err(),
		Some(ProtocolError::NoSession)
	);
	assert_eq!(
		receive_as_peer(&mut server, 20000, &expired),
		Err(ProtocolError::Rejected)
	);
	assert!(server.tunnel.current_transport_key().is_none());
	let fresh = outer(
		client.send(&ipv4(A, B), &mut wire).unwrap(),
		endpoint(20001),
	);
	assert_eq!(receive_as_peer(&mut server, 20000, fresh), Ok(true));
	assert_eq!(select_key(&server), new);
	assert!(matches!(
		server.tunnel.decapsulate(None, &[], &mut wire),
		TunnResult::Done
	));
}

#[test]
fn previous_completion_cannot_renew_but_current_completion_can() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	let old = select_key(&client);
	advance(&mut client, &mut server, 61);
	let mut wire = [0; MAX_DATAGRAM_BYTES];
	let mut output = [0; MAX_DATAGRAM_BYTES];
	let first = outer(client.initiate(&mut wire).unwrap(), endpoint(20001));
	let previous = outer(
		server.receive(endpoint(20000), first, &mut output).unwrap(),
		endpoint(20000),
	)
	.to_vec();

	// Force the second pending attempt without relying on a real five-second timer.
	let TunnResult::WriteToNetwork(retry) =
		client.tunnel.format_handshake_initiation(&mut wire, true)
	else {
		panic!("expected an actual WireGuard retry");
	};
	let current = outer(
		server.receive(endpoint(20000), retry, &mut output).unwrap(),
		endpoint(20000),
	)
	.to_vec();

	client.operations_remaining = 2;
	client.handshakes_remaining = 2;
	assert_eq!(
		receive_as_peer(&mut client, 20001, &previous),
		Err(ProtocolError::Rejected)
	);
	assert_eq!(client.operations_remaining, 1);
	assert_eq!(client.handshakes_remaining, 1);
	let confirmation = outer(
		client
			.receive(endpoint(20001), &current, &mut output)
			.unwrap(),
		endpoint(20001),
	);
	assert_ne!(select_key(&client), old);
	assert_eq!(client.operations_remaining, MAX_GENERATION_OPERATIONS - 1);
	assert_eq!(client.handshakes_remaining, MAX_INCOMING_HANDSHAKES - 1);
	assert_eq!(receive_as_peer(&mut server, 20000, confirmation), Ok(false));
	assert_eq!(
		receive_as_peer(&mut client, 20001, &current),
		Err(ProtocolError::Rejected)
	);
}

#[test]
fn exhausted_or_expired_wrapper_rejects_even_a_valid_pending_response() {
	for time_limit in [false, true] {
		let (mut client, mut server) = peers(A.into(), B.into(), B.into());
		handshake(&mut client, &mut server);
		let old = select_key(&client);
		let mut wire = [0; MAX_DATAGRAM_BYTES];
		let mut response = [0; MAX_DATAGRAM_BYTES];
		let initiation = outer(client.initiate(&mut wire).unwrap(), endpoint(20001));
		let pending = outer(
			server
				.receive(endpoint(20000), initiation, &mut response)
				.unwrap(),
			endpoint(20000),
		);
		let expected = if time_limit {
			client.clock.advance_for_test(Duration::from_secs(120));
			ProtocolError::Expired
		} else {
			client.operations_remaining = 0;
			ProtocolError::OperationLimit
		};
		assert_eq!(receive_as_peer(&mut client, 20001, pending), Err(expected));
		assert_eq!(select_key(&client), old);
	}
}

#[test]
fn unconfirmed_responder_selection_cannot_send_or_extend_bootstrap() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	let mut wire = [0; MAX_DATAGRAM_BYTES];
	let mut output = [0; MAX_DATAGRAM_BYTES];
	assert_eq!(
		server.send(&ipv4(B, A), &mut output).err(),
		Some(ProtocolError::NoSession)
	);
	assert!(matches!(server.tick(&mut output), Ok(PacketOutput::None)));
	for _ in 0..8 {
		let TunnResult::WriteToNetwork(initiation) =
			client.tunnel.format_handshake_initiation(&mut wire, true)
		else {
			panic!("expected a WireGuard initiation");
		};
		let response = outer(
			server
				.receive(endpoint(20000), initiation, &mut output)
				.unwrap(),
			endpoint(20000),
		);
		assert!(matches!(
			Tunn::parse_incoming_packet(response),
			Ok(Packet::HandshakeResponse(_))
		));
	}
	assert!(server.tunnel.current_transport_key().is_some());
	assert!(!server.observation().has_session);
	assert_eq!(
		server.send(&ipv4(B, A), &mut output).err(),
		Some(ProtocolError::NoSession)
	);
	assert!(matches!(server.tick(&mut output), Ok(PacketOutput::None)));
	assert!(matches!(
		server.tunnel.decapsulate(None, &[], &mut output),
		TunnResult::Done
	));
	server.clock.advance_for_test(Duration::from_secs(120));
	assert_eq!(server.tick(&mut output).err(), Some(ProtocolError::Expired));
}

#[cfg(feature = "experimental-udp")]
#[test]
fn pending_old_key_effect_is_rechecked_at_egress_and_cannot_reuse_stamp() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	let mut wire = [0; MAX_DATAGRAM_BYTES];
	let delayed = outer(
		client.send(&ipv4(A, B), &mut wire).unwrap(),
		endpoint(20001),
	)
	.to_vec();
	advance(&mut client, &mut server, 61);
	complete_rekey(&mut client, &mut server);
	assert_eq!(receive_as_peer(&mut server, 20000, &delayed), Ok(true));

	let valid = server.send(&ipv4(B, A), &mut wire).unwrap();
	assert_eq!(server.check_output(&valid), Ok(()));
	assert_eq!(server.check_output(&valid), Err(ProtocolError::Rejected));
	let pending = server.send(&ipv4(B, A), &mut wire).unwrap();
	server.clock.advance_for_test(Duration::from_secs(60));
	assert_eq!(server.check_generation(), Ok(()));
	assert_eq!(server.check_output(&pending), Err(ProtocolError::Rejected));
}

#[test]
fn closely_spaced_new_keys_cannot_immediately_refill_wrapper_work() {
	let (mut client, mut server) = peers(A.into(), B.into(), B.into());
	handshake(&mut client, &mut server);
	let mut wire = [0; MAX_DATAGRAM_BYTES];
	let mut reply = [0; MAX_DATAGRAM_BYTES];
	advance(&mut client, &mut server, 1);
	client.operations_remaining = 3;
	complete_rekey(&mut client, &mut server);
	assert_eq!(client.operations_remaining, 1);

	advance(&mut client, &mut server, 5);
	let data = outer(
		client.send(&ipv4(A, B), &mut wire).unwrap(),
		endpoint(20001),
	);
	assert_eq!(client.operations_remaining, MAX_GENERATION_OPERATIONS - 1);
	assert!(matches!(
		server.receive(endpoint(20000), data, &mut reply),
		Ok(PacketOutput::Inner(_))
	));
}
