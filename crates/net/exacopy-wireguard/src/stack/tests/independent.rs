use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::protocol::INNER_MTU;

use super::{
	InnerMtu, InnerTcp, LiveTcp, PacketDisposition, ReadProgress, Socket, TcpError, TcpFlow,
	TcpState, ipv4_flow, ipv6_flow,
};

#[test]
fn mtu_is_maximal_and_padding_safe_for_all_outer_budget_values() {
	for (peer, overhead) in [
		(SocketAddr::from((Ipv4Addr::LOCALHOST, 51820)), 60),
		(SocketAddr::from((Ipv6Addr::LOCALHOST, 51820)), 80),
	] {
		let mut previous = 0;
		for outer in 0..=u16::MAX {
			match InnerMtu::from_outer(peer, outer) {
				Ok(mtu) => {
					let inside = mtu.bytes();
					assert!(previous <= inside);
					assert!((576..=INNER_MTU).contains(&inside));
					assert!(overhead + padded(inside) <= usize::from(outer));
					if inside < INNER_MTU {
						assert!(overhead + padded(inside + 1) > usize::from(outer));
					}
					previous = inside;
				}
				Err(TcpError::Mtu) => {
					assert_eq!(previous, 0);
					assert!(usize::from(outer) < overhead + padded(576));
				}
				Err(error) => panic!("unexpected MTU result: {error}"),
			}
		}
	}
}

fn padded(length: usize) -> usize {
	length + (16 - length % 16) % 16
}

#[test]
fn full_segments_fit_cross_family_outer_budgets_at_inner_minimums() {
	for (mut flow, outer_peer, outer_mtu, expected) in [
		(
			ipv4_flow(),
			SocketAddr::from((Ipv6Addr::LOCALHOST, 51820)),
			656,
			576,
		),
		(
			ipv6_flow(),
			SocketAddr::from((Ipv4Addr::LOCALHOST, 51820)),
			1340,
			1280,
		),
	] {
		let lower = InnerMtu::from_outer(outer_peer, outer_mtu - 1);
		if flow.local.is_ipv6() {
			flow.mtu = lower.unwrap();
			let one_below = TcpFlow { ..flow };
			assert!(matches!(
				InnerTcp::connect(one_below, 1),
				Err(TcpError::Mtu)
			));
		} else {
			assert!(matches!(lower, Err(TcpError::Mtu)));
		}
		flow.mtu = InnerMtu::from_outer(outer_peer, outer_mtu).unwrap();
		assert_eq!(flow.mtu.bytes(), expected);
		transfer_at_minimum(flow);
	}
}

fn transfer_at_minimum(flow: TcpFlow) {
	let mtu = flow.mtu.bytes();
	let incoming = TcpFlow {
		binding: flow.binding,
		local: flow.remote,
		remote: flow.local,
		mtu: flow.mtu,
	};
	let mut listening = LiveTcp::new(&incoming, 11).unwrap();
	listening
		.sockets
		.get_mut::<Socket<'_>>(listening.handle)
		.listen(incoming.local)
		.unwrap();
	let mut server = InnerTcp {
		flow: incoming,
		live: Some(listening),
	};
	let mut client = InnerTcp::connect(flow, 17).unwrap();
	let data: [u8; 6007] = std::array::from_fn(|index| (index % 251) as u8);
	let mut received = Vec::with_capacity(data.len());
	let mut written = 0;
	let mut full_segment = false;
	for step in 0..1000 {
		let now = Duration::from_millis(step);
		client.poll(now).unwrap();
		server.poll(now).unwrap();
		full_segment |= deliver(&mut client, &mut server, mtu);
		deliver(&mut server, &mut client, mtu);
		if client.state() == TcpState::Writable {
			written += client.write(&data[written..]).unwrap();
		}
		if server.state() == TcpState::Writable {
			let mut chunk = [0; 443];
			if let ReadProgress::Bytes(count) = server.read(&mut chunk).unwrap() {
				received.extend_from_slice(&chunk[..count.get()]);
			}
		}
		if received.len() == data.len() {
			break;
		}
	}
	assert_eq!(received, data);
	assert!(
		full_segment,
		"the transfer must exercise the exact packet ceiling"
	);
}

fn deliver(source: &mut InnerTcp, sink: &mut InnerTcp, mtu: usize) -> bool {
	let mut full_segment = false;
	source
		.egress(|_, packet| {
			assert!(packet.len() <= mtu);
			match sink.ingress(packet) {
				Ok(()) => {
					full_segment = packet.len() == mtu;
					Ok::<_, Infallible>(PacketDisposition::Accepted)
				}
				Err(TcpError::IngressFull) => Ok(PacketDisposition::Backpressure),
				Err(error) => panic!("independent in-memory receiver refused packet: {error}"),
			}
		})
		.unwrap();
	full_segment
}
