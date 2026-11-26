use super::*;
use crate::protocol::INNER_MTU;

use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::num::{NonZeroU64, NonZeroU128};

fn flow(local: SocketAddr, remote: SocketAddr) -> TcpFlow {
	TcpFlow {
		binding: PeerBinding {
			revision: [7; 32],
			actor: NonZeroU128::new(1).unwrap(),
			generation: NonZeroU64::new(2).unwrap(),
		},
		local,
		remote,
		mtu: InnerMtu::from_outer(remote, 1500).unwrap(),
	}
}

pub(super) fn ipv4_flow() -> TcpFlow {
	flow(
		SocketAddr::from((Ipv4Addr::new(10, 75, 1, 4), 49_152)),
		SocketAddr::from((Ipv4Addr::new(10, 85, 1, 5), 22)),
	)
}

pub(super) fn ipv6_flow() -> TcpFlow {
	flow(
		SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 4), 49_152)),
		SocketAddr::from((Ipv6Addr::new(0xfd00, 0, 0, 2, 0, 0, 0, 5), 22)),
	)
}

pub(super) fn pair(route: TcpFlow) -> (InnerTcp, InnerTcp) {
	let incoming = flow(route.remote, route.local);
	(InnerTcp::connect(route, 1).unwrap(), passive(incoming))
}

pub(crate) fn passive(incoming: TcpFlow) -> InnerTcp {
	let mut listening = LiveTcp::new(&incoming, 2).unwrap();
	listening
		.sockets
		.get_mut::<Socket<'_>>(listening.handle)
		.listen(incoming.local)
		.unwrap();

	InnerTcp {
		flow: incoming,
		live: Some(listening),
	}
}

fn deliver(tx: &mut InnerTcp, rx: &mut InnerTcp) {
	tx.egress(|_, packet| match rx.ingress(packet) {
		Ok(()) => Ok(PacketDisposition::Accepted),
		Err(TcpError::IngressFull) => Ok(PacketDisposition::Backpressure),
		Err(error) => Err(error),
	})
	.unwrap();
}

fn tick(client: &mut InnerTcp, peer: &mut InnerTcp, now: u64) {
	let elapsed = Duration::from_millis(now);
	client.poll(elapsed).unwrap();
	peer.poll(elapsed).unwrap();
	deliver(client, peer);
	deliver(peer, client);
}

fn connect_pair(route: TcpFlow) -> (InnerTcp, InnerTcp, u64) {
	let (mut client, mut peer) = pair(route);
	for now in 0..100 {
		tick(&mut client, &mut peer, now);
		if client.state() == TcpState::Writable && peer.state() == TcpState::Writable {
			return (client, peer, now + 1);
		}
	}
	panic!("in-memory TCP handshake did not complete");
}

fn write_all(tcp: &mut InnerTcp, data: &[u8], sent: &mut usize) {
	*sent += tcp.write(&data[*sent..]).unwrap();
}

fn read_available(tcp: &mut InnerTcp, output: &mut Vec<u8>) -> ReadProgress {
	let mut buffer = [0; 997];
	let read = tcp.read(&mut buffer).unwrap();
	if let ReadProgress::Bytes(count) = read {
		output.extend_from_slice(&buffer[..count.get()]);
	}
	read
}

fn exact_bidirectional_transfer(route: TcpFlow) {
	let (mut client, mut peer, start) = connect_pair(route);
	let upload: Vec<_> = (0..(STREAM_BUFFER_BYTES * 4))
		.map(|index| (index % 251) as u8)
		.collect();
	let download: Vec<_> = (0..(STREAM_BUFFER_BYTES * 3))
		.map(|index| (index % 131) as u8)
		.collect();
	let mut client_written = 0;
	let mut peer_written = 0;
	let mut client_read = Vec::new();
	let mut peer_read = Vec::new();

	for now in start..3_000 {
		tick(&mut client, &mut peer, now);
		write_all(&mut client, &upload, &mut client_written);
		write_all(&mut peer, &download, &mut peer_written);
		read_available(&mut client, &mut client_read);
		read_available(&mut peer, &mut peer_read);
		if client_read.len() == download.len() && peer_read.len() == upload.len() {
			break;
		}
	}
	assert_eq!(client_read, download);
	assert_eq!(peer_read, upload);
}

#[test]
fn exchanges_more_than_the_stream_windows_over_ipv4_and_ipv6() {
	exact_bidirectional_transfer(ipv4_flow());
	exact_bidirectional_transfer(ipv6_flow());
}

fn next_packet(tcp: &mut InnerTcp) -> Vec<u8> {
	let mut captured = None;
	let result = tcp
		.egress(|_, bytes| {
			captured = Some(bytes.to_vec());
			Ok::<_, Infallible>(PacketDisposition::Accepted)
		})
		.unwrap();
	assert_eq!(result, Some(PacketDisposition::Accepted));
	captured.unwrap()
}

#[test]
fn backpressure_holds_one_packet_and_blocks_another_ingress() {
	let (mut client, mut peer) = pair(ipv4_flow());
	assert_eq!(client.poll(Duration::ZERO).unwrap(), PollHint::Egress);
	let mut held = Vec::new();
	assert_eq!(
		client
			.egress(|_, bytes| {
				held.extend(bytes);
				Ok::<_, Infallible>(PacketDisposition::Backpressure)
			})
			.unwrap(),
		Some(PacketDisposition::Backpressure)
	);
	assert_eq!(
		client.egress(|_, bytes| {
			assert_eq!(held, bytes);
			Err::<PacketDisposition, _>("owner refused emission")
		}),
		Err("owner refused emission")
	);
	let syn = next_packet(&mut client);
	assert_eq!(syn, held);
	assert_eq!(peer.ingress(&syn), Ok(()));
	assert_eq!(peer.ingress(&syn), Err(TcpError::IngressFull));
	assert_eq!(peer.poll(Duration::ZERO).unwrap(), PollHint::Egress);
	assert!(next_packet(&mut peer).len() <= INNER_MTU);
}

#[test]
fn local_send_queue_backpressures_until_the_peer_can_receive() {
	let (mut client, mut peer, start) = connect_pair(ipv4_flow());
	let input = vec![42; STREAM_BUFFER_BYTES * 2];
	assert_eq!(client.write(&input).unwrap(), STREAM_BUFFER_BYTES);
	assert_eq!(client.write(&input).unwrap(), 0);
	tick(&mut client, &mut peer, start);
	assert_eq!(client.write(&input).unwrap(), 0);
	let accepted = (start + 1..3_000).any(|now| {
		tick(&mut client, &mut peer, now);
		client.write(&input).unwrap() > 0
	});
	assert!(accepted);
}

#[test]
fn loss_retransmits_the_active_open_on_the_caller_clock() {
	let (mut client, mut peer) = pair(ipv4_flow());
	assert_eq!(client.poll(Duration::ZERO).unwrap(), PollHint::Egress);
	let dropped = next_packet(&mut client);
	let PollHint::At(next) = client.poll(Duration::ZERO).unwrap() else {
		panic!("the initial SYN should schedule retransmission");
	};
	assert!(next > MIN_TIMER_DELAY);
	assert_ne!(
		client.poll(next - MIN_TIMER_DELAY).unwrap(),
		PollHint::Egress
	);
	assert_eq!(client.poll(next).unwrap(), PollHint::Egress);
	assert_eq!(next_packet(&mut client), dropped);
	peer.ingress(&dropped).unwrap();
	for now in u64::try_from(next.as_millis()).unwrap()..3_000 {
		tick(&mut client, &mut peer, now);
		if client.state() == TcpState::Writable && peer.state() == TcpState::Writable {
			return;
		}
	}
	panic!("the retransmitted SYN should connect");
}

#[test]
fn source_scope_rejects_wrong_direction_ports_format_and_limits() {
	for route in [ipv4_flow(), ipv6_flow()] {
		let address = route.local.ip();
		let distinct_address = match address {
			std::net::IpAddr::V4(_) => Ipv4Addr::new(10, 18, 1, 7).into(),
			std::net::IpAddr::V6(_) => Ipv6Addr::new(0xfd00, 0, 0, 3, 0, 0, 0, 7).into(),
		};
		let distinct = flow(
			SocketAddr::new(distinct_address, route.local.port()),
			route.remote,
		);
		let mut outsider = InnerTcp::connect(distinct, 4).unwrap();
		assert_eq!(outsider.poll(Duration::ZERO).unwrap(), PollHint::Egress);
		let outsider_packet = next_packet(&mut outsider);
		let (mut client, mut peer) = pair(route);
		assert_eq!(peer.ingress(&outsider_packet), Err(TcpError::FlowMismatch));
		assert_eq!(client.poll(Duration::ZERO).unwrap(), PollHint::Egress);
		let packet = next_packet(&mut client);
		assert_eq!(client.ingress(&packet), Err(TcpError::FlowMismatch));
		let mut wrong_port = packet.clone();
		let start = if address.is_ipv4() { 20 } else { 40 };
		wrong_port[start + 3] ^= 1;
		assert_eq!(peer.ingress(&wrong_port), Err(TcpError::FlowMismatch));
		let mut wrong_checksum = packet.clone();
		wrong_checksum[start + 16] ^= 1;
		assert_eq!(peer.ingress(&wrong_checksum), Err(TcpError::Packet));
		let mut wrong_protocol = packet.clone();
		let offset = if address.is_ipv4() { 9 } else { 6 };
		wrong_protocol[offset] = 17;
		assert_eq!(peer.ingress(&wrong_protocol), Err(TcpError::Packet));
		if address.is_ipv4() {
			let mut fragment = packet.clone();
			fragment[6] |= 0x20;
			assert_eq!(peer.ingress(&fragment), Err(TcpError::Packet));
			let mut options = packet.clone();
			options[0] = 0x46;
			assert_eq!(peer.ingress(&options), Err(TcpError::Packet));
		}
		assert_eq!(peer.ingress(&[0; INNER_MTU + 1]), Err(TcpError::Packet));
		for length in 0..packet.len() {
			assert_eq!(peer.ingress(&packet[..length]), Err(TcpError::Packet));
		}
		assert_eq!(peer.ingress(&packet), Ok(()));
	}
}

#[test]
fn malformed_or_ambiguous_endpoints_are_refused() {
	let selected = ipv4_flow();
	for remote in [
		SocketAddr::from((Ipv4Addr::UNSPECIFIED, 22)),
		SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 22)),
		SocketAddr::from((Ipv4Addr::BROADCAST, 22)),
		SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
		SocketAddr::from((Ipv6Addr::LOCALHOST, 22)),
		SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 22, 0, 1)),
		SocketAddr::from((selected.local.ip(), 22)),
	] {
		assert!(matches!(
			InnerTcp::connect(flow(selected.local, remote), 1),
			Err(TcpError::InvalidFlow)
		));
	}
}

#[test]
fn graceful_eof_follows_buffered_data_and_preserves_the_other_direction() {
	let (mut client, mut peer, start) = connect_pair(ipv4_flow());
	let message = b"final data";
	assert_eq!(client.write(message), Ok(message.len()));
	client.close_send().unwrap();
	assert_eq!(client.write(message), Err(TcpError::Closed));
	let mut received = Vec::new();
	for now in start..3_000 {
		tick(&mut client, &mut peer, now);
		if read_available(&mut peer, &mut received) == ReadProgress::Eof {
			assert_eq!(received, message);
			assert_eq!(peer.write(b"still sending"), Ok(13));
			return;
		}
	}
	panic!("closing the send half did not deliver EOF");
}

#[test]
fn fencing_drops_packet_slots_and_rejects_later_activity() {
	let mut client = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	assert_eq!(
		client.poll(Duration::from_millis(50)).unwrap(),
		PollHint::Egress
	);
	assert_eq!(client.poll(Duration::from_millis(49)), Err(TcpError::Clock));
	assert_eq!(
		client.egress(|_, _| -> Result<PacketDisposition, Infallible> {
			panic!("fenced flow exposed a packet")
		}),
		Ok(None)
	);
	assert_eq!(client.state(), TcpState::Closed);
	assert_eq!(client.read(&mut [0; 1]), Err(TcpError::Closed));
	assert_eq!(client.write(b"late"), Err(TcpError::Closed));
	assert_eq!(client.ingress(b"late"), Err(TcpError::Closed));
	assert_eq!(
		client.poll(Duration::from_millis(50)),
		Err(TcpError::Closed)
	);

	let mut client = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	assert_eq!(
		client.poll(Duration::from_millis(u64::from(u32::MAX) + 1)),
		Err(TcpError::Clock)
	);
	assert_eq!(client.close_send(), Err(TcpError::Closed));
}

#[test]
fn unexpected_stack_egress_fences_before_exposing_the_packet() {
	let mut client = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	client
		.live
		.as_mut()
		.unwrap()
		.device
		.tx
		.queue(b"invalid output");
	assert_eq!(client.poll(Duration::ZERO), Err(TcpError::Packet));
	assert_eq!(client.state(), TcpState::Closed);
	assert_eq!(
		client.egress(|_, _| -> Result<PacketDisposition, Infallible> {
			panic!("invalid stack output reached the route owner")
		}),
		Ok(None)
	);
}

mod wireguard;

#[test]
fn an_ack_covering_a_packet_held_at_egress_is_refused_until_submission() {
	let (mut client, mut peer) = pair(ipv4_flow());
	assert_eq!(client.poll(Duration::ZERO).unwrap(), PollHint::Egress);

	// The local fixture observes the packet to produce an ordinary SYN-ACK,
	// while the egress owner explicitly refuses to commit the held SYN.
	assert_eq!(
		client.egress(|_, syn| {
			peer.ingress(syn)?;
			Ok::<_, TcpError>(PacketDisposition::Backpressure)
		}),
		Ok(Some(PacketDisposition::Backpressure))
	);
	assert_eq!(peer.poll(Duration::ZERO).unwrap(), PollHint::Egress);
	let acknowledgement = next_packet(&mut peer);
	assert_eq!(
		client.ingress(&acknowledgement),
		Err(TcpError::Acknowledgement)
	);

	next_packet(&mut client);
	assert_eq!(client.ingress(&acknowledgement), Ok(()));
}

#[test]
fn mtu_accounts_for_outer_address_family_and_wireguard_padding() {
	let v4 = ipv4_flow().remote;
	let v6 = ipv6_flow().remote;
	assert_eq!(InnerMtu::from_outer(v4, 1500).unwrap().bytes(), 1420);
	assert_eq!(InnerMtu::from_outer(v6, 1500).unwrap().bytes(), 1408);
	assert_eq!(InnerMtu::from_outer(v6, 1504).unwrap().bytes(), 1420);

	for minimum in [0, 655] {
		assert!(matches!(
			InnerMtu::from_outer(v6, minimum),
			Err(TcpError::Mtu)
		));
	}
	let undersized = InnerMtu::from_outer(v6, 1359).unwrap();
	assert!(undersized.bytes() < IPV6_INNER_MIN);
	assert!(matches!(
		InnerTcp::connect(
			TcpFlow {
				mtu: undersized,
				..ipv6_flow()
			},
			1
		),
		Err(TcpError::Mtu)
	));
}

#[test]
fn an_ack_for_queued_data_cannot_remove_unsubmitted_bytes() {
	let flow = ipv4_flow();
	let local = flow.local;
	let remote = flow.remote;
	let mtu = flow.mtu.bytes();
	let (mut client, mut peer, start) = connect_pair(flow);
	let body = b"tracked test bytes";
	assert_eq!(client.write(body), Ok(body.len()));
	assert_eq!(
		client.poll(Duration::from_millis(start)),
		Ok(PollHint::Egress)
	);

	assert_eq!(
		client.egress(|_, packet| {
			let projection = packet::parse(packet, local, remote, mtu)?;
			assert_eq!(projection.segment.payload as usize, body.len());
			peer.ingress(packet)?;
			Ok::<_, TcpError>(PacketDisposition::Backpressure)
		}),
		Ok(Some(PacketDisposition::Backpressure))
	);
	let peer_poll = (start..start + 100)
		.find(|&now| peer.poll(Duration::from_millis(now)) == Ok(PollHint::Egress));
	assert!(peer_poll.is_some());
	let acknowledgement = next_packet(&mut peer);
	assert_eq!(
		client.ingress(&acknowledgement),
		Err(TcpError::Acknowledgement)
	);
	assert_eq!(
		client.live.as_ref().unwrap().socket().send_queue(),
		body.len()
	);

	next_packet(&mut client);
	assert_eq!(client.ingress(&acknowledgement), Ok(()));
}

#[path = "tests/independent.rs"]
mod independent;
