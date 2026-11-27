use smoltcp::wire::{IpAddress, Ipv4Packet, TcpPacket};

use super::*;

fn state(tcp: &InnerTcp) -> State {
	tcp.live.as_ref().unwrap().socket().state()
}

fn reset_reply(mut packet: Vec<u8>) -> Vec<u8> {
	let mut ipv4 = Ipv4Packet::new_checked(packet.as_mut_slice()).unwrap();
	let source = ipv4.dst_addr();
	let target = ipv4.src_addr();
	ipv4.set_src_addr(source);
	ipv4.set_dst_addr(target);
	ipv4.fill_checksum();
	let mut tcp = TcpPacket::new_checked(ipv4.payload_mut()).unwrap();
	assert!(tcp.payload_mut().is_empty());
	let source_port = tcp.dst_port();
	let target_port = tcp.src_port();
	let sequence = tcp.ack_number();
	let acknowledgement = tcp.seq_number() + usize::from(tcp.fin());
	tcp.set_src_port(source_port);
	tcp.set_dst_port(target_port);
	tcp.set_seq_number(sequence);
	tcp.set_ack_number(acknowledgement);
	tcp.set_fin(false);
	tcp.set_rst(true);
	tcp.fill_checksum(&IpAddress::from(source), &IpAddress::from(target));
	packet
}

#[test]
fn reset_after_peer_fin_is_never_a_graceful_close_in_closing_last_ack_or_time_wait() {
	for expected in [State::Closing, State::LastAck, State::TimeWait] {
		let (mut local, mut peer, start) = connect_pair(ipv4_flow());
		let advanced = start + 32;
		match expected {
			State::Closing => {
				// Cross both FINs before either is acknowledged.
				local.close_send().unwrap();
				peer.close_send().unwrap();
				tick(&mut local, &mut peer, start);
			}
			State::LastAck => {
				peer.close_send().unwrap();
				for now in start..advanced {
					tick(&mut local, &mut peer, now);
				}
				assert_eq!(state(&local), State::CloseWait);
				local.close_send().unwrap();
			}
			State::TimeWait => {
				local.close_send().unwrap();
				for now in start..advanced {
					tick(&mut local, &mut peer, now);
				}
				assert_eq!(state(&local), State::FinWait2);
				peer.close_send().unwrap();
				peer.poll(Duration::from_millis(advanced)).unwrap();
				deliver(&mut peer, &mut local);
			}
			_ => unreachable!(),
		}
		let (time, final_packet) = (advanced + 1..=advanced + 20)
			.find_map(|now| {
				let time = Duration::from_millis(now);
				(local.poll(time).unwrap() == PollHint::Egress)
					.then(|| (time, next_packet(&mut local)))
			})
			.expect("the test peer FIN must produce a local packet");
		assert_eq!(state(&local), expected);
		assert_eq!(local.read(&mut [0; 1]).unwrap(), ReadProgress::Eof);
		local.ingress(&reset_reply(final_packet)).unwrap();
		assert_eq!(
			local.poll(time + Duration::from_millis(1)),
			Err(TcpError::Reset),
			"an accepted reset in {expected:?} must fence before the driver can observe closure"
		);
		assert!(!local.finished());
	}
}
