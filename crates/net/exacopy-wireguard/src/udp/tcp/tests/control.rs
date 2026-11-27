use super::super::tests::{Owner, pair};
use super::*;
use crate::protocol::{MAX_DATAGRAM_BYTES, PublicKey, StaticSecret};
use crate::udp::UdpProgress;
use crate::udp::tests::{LOCAL, REMOTE, binding, fixture_ip, run};

const WAIT_LIMIT: Duration = Duration::from_millis(50);
const BLOCKED: PacketInterest = PacketInterest {
	receive: false,
	writable: false,
};
const OPEN: PacketInterest = PacketInterest {
	receive: true,
	writable: false,
};
const EXTRA_CONTROL_LIMIT: usize = 8;

async fn blocked_wait(io: &mut UdpPacketIo<Owner>) {
	let mut packet = [37; INNER_MTU];
	assert!(
		tokio::time::timeout(WAIT_LIMIT, io.wait(BLOCKED, &mut packet))
			.await
			.is_err(),
		"blocked control must not report TCP progress or terminate the actor"
	);
	assert_eq!(packet, [37; INNER_MTU]);
}

async fn receive_exact(io: &mut UdpPacketIo<Owner>, payload: &[u8]) {
	let mut packet = [0; INNER_MTU];
	let event = tokio::time::timeout(Duration::from_secs(2), io.wait(OPEN, &mut packet))
		.await
		.unwrap()
		.unwrap();
	assert!(matches!(event, PacketEvent::Received(count) if count == payload.len()));
	assert_eq!(&packet[..payload.len()], payload);
}

fn rejected_initiation(contributory: bool) -> [u8; 148] {
	let mut packet = [0; 148];
	packet[..4].copy_from_slice(&1_u32.to_le_bytes());
	if contributory {
		let public = PublicKey::from(&StaticSecret::from([11; 32])).to_bytes();
		packet[8..40].copy_from_slice(&public);
	}
	// The all-zero authentication fields deliberately cannot authenticate.
	packet
}

#[test]
fn invalid_and_rejected_control_exhaust_only_the_blocked_receive_budget() {
	run(async {
		let (_, mut first, _, second) = pair().await;
		let mut second = UdpPacketIo::new(second, binding(2)).unwrap();
		for ordinal in 0..EXTRA_CONTROL_LIMIT {
			let packet = rejected_initiation(ordinal % 2 == 0);
			let sender = &first.active.as_ref().unwrap().socket;
			assert_eq!(sender.send(&packet).await.unwrap(), packet.len());
		}
		let mut marker = rejected_initiation(false);
		marker[4] = 29;
		let sender = &first.active.as_ref().unwrap().socket;
		assert_eq!(sender.send(&marker).await.unwrap(), marker.len());
		for _ in 0..3 {
			blocked_wait(&mut second).await;
			assert!(!second.peer.blocked_control_available());
			let protocol = &second.peer.active.as_ref().unwrap().protocol;
			assert_eq!(protocol.blocked_control_allowance_for_test(), 0);
			assert!(second.peer.session_ready().unwrap());
			let socket = &second.peer.active.as_ref().unwrap().socket;
			let mut head = [0; MAX_DATAGRAM_BYTES + 1];
			assert_eq!(socket.try_peek(&mut head).unwrap(), marker.len());
			assert_eq!(&head[..marker.len()], &marker);
		}

		// The ordinary receive path retains its direct typed error semantics.
		let mut wire = [0; MAX_DATAGRAM_BYTES];
		assert!(matches!(
			second.peer.receive_ready(&mut wire),
			Err(UdpError::Protocol(
				crate::protocol::ProtocolError::NonContributoryEphemeral
			))
		));
		let payload = fixture_ip(LOCAL, REMOTE);
		assert!(matches!(
			first.send_inner(&payload, &mut wire),
			Ok(UdpProgress::Sent)
		));
		receive_exact(&mut second, &payload).await;
		assert!(!second.peer.blocked_control_available());
	});
}

#[test]
fn data_remains_in_fifo_order_ahead_of_blocked_control() {
	run(async {
		let (_, mut first, _, second) = pair().await;
		let mut second = UdpPacketIo::new(second, binding(2)).unwrap();
		let mut wire = [0; MAX_DATAGRAM_BYTES];
		let first_payload = fixture_ip(LOCAL, REMOTE);
		let mut second_payload = first_payload;
		second_payload[20] = 29;
		for payload in [first_payload, second_payload] {
			assert!(matches!(
				first.send_inner(&payload, &mut wire),
				Ok(UdpProgress::Sent)
			));
		}
		let behind = rejected_initiation(false);
		let sender = &first.active.as_ref().unwrap().socket;
		assert_eq!(sender.send(&behind).await.unwrap(), behind.len());
		blocked_wait(&mut second).await;
		assert!(second.peer.blocked_control_available());
		receive_exact(&mut second, &first_payload).await;
		receive_exact(&mut second, &second_payload).await;
		let socket = &second.peer.active.as_ref().unwrap().socket;
		let mut head = [0; MAX_DATAGRAM_BYTES + 1];
		tokio::time::timeout(WAIT_LIMIT, socket.readable())
			.await
			.unwrap()
			.unwrap();
		assert_eq!(socket.try_peek(&mut head).unwrap(), behind.len());
		assert_eq!(&head[..behind.len()], &behind);
		blocked_wait(&mut second).await;
		let socket = &second.peer.active.as_ref().unwrap().socket;
		let mut head = [0; MAX_DATAGRAM_BYTES + 1];
		assert!(
			matches!(socket.try_peek(&mut head), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
		);
	});
}

#[test]
fn fifo_head_rekey_advances_with_ingress_blocked() {
	run(async {
		let (_, mut first, _, second) = pair().await;
		let mut second = UdpPacketIo::new(second, binding(2)).unwrap();
		let sender = &mut first.active.as_mut().unwrap().protocol;
		let receiver = &mut second.peer.active.as_mut().unwrap().protocol;
		let old = [
			sender.current_renewal_key_for_test(),
			receiver.current_renewal_key_for_test(),
		];
		sender.advance_rekey_clock_for_test(Duration::from_secs(61));
		receiver.advance_rekey_clock_for_test(Duration::from_secs(61));
		assert!(old.iter().all(Option::is_some));
		// Leave exactly the two speculative steps needed for the peer's
		// initiation and authenticated empty confirmation.
		for _ in 0..(EXTRA_CONTROL_LIMIT - 2) {
			assert!(receiver.reserve_blocked_control().is_some());
		}
		let mut wire = [0; MAX_DATAGRAM_BYTES];
		assert!(matches!(first.tick(&mut wire), Ok(UdpProgress::Sent)));
		// Do not let the responder start a simultaneous proactive renewal.
		second.next_tick = tokio::time::Instant::now() + Duration::from_secs(2);
		let mut packet = [0; INNER_MTU];
		tokio::time::timeout(Duration::from_secs(1), async {
			tokio::select! {
				event = second.wait(BLOCKED, &mut packet) => {
					panic!("blocked rekey returned a TCP event or error: {:?}", event.err());
				}
				() = async {
					loop {
						match first.receive_one(WAIT_LIMIT, &mut wire).await.unwrap() {
							UdpProgress::Sent => break,
							UdpProgress::NoDatagram => {}
							_ => panic!("expected responder handshake"),
						}
					}
				} => {}
			}
		})
		.await
		.unwrap();
		let initiator = &first.active.as_ref().unwrap().protocol;
		assert!(initiator.current_renewal_key_for_test().is_some());
		assert_ne!(initiator.current_renewal_key_for_test(), old[0]);
		// The initiator submitted confirmation while the wait was suspended.
		// Installation of the responder key alone must not restore the quota.
		let responder = &second.peer.active.as_ref().unwrap().protocol;
		assert_eq!(responder.current_renewal_key_for_test(), old[1]);
		assert_eq!(responder.blocked_control_allowance_for_test(), 1);
		blocked_wait(&mut second).await;
		assert!(second.peer.session_ready().unwrap());
		let receiver = &mut second.peer.active.as_mut().unwrap().protocol;
		assert!(receiver.current_renewal_key_for_test().is_some());
		assert_ne!(receiver.current_renewal_key_for_test(), old[1]);
		for _ in 0..EXTRA_CONTROL_LIMIT {
			assert!(receiver.reserve_blocked_control().is_some());
		}
		assert!(receiver.reserve_blocked_control().is_none());
		let payload = fixture_ip(LOCAL, REMOTE);
		assert!(matches!(
			first.send_inner(&payload, &mut wire),
			Ok(UdpProgress::Sent)
		));
		receive_exact(&mut second, &payload).await;
	});
}
