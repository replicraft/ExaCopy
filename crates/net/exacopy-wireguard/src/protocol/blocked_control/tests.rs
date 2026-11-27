use std::net::{Ipv4Addr, SocketAddr};
use std::num::{NonZeroU64, NonZeroU128};

use super::*;
use crate::protocol::{PeerAddresses, PeerBinding, PublicKey, StaticSecret};

fn peer() -> ProtocolPeer {
	ProtocolPeer::new(
		PeerBinding {
			actor: NonZeroU128::MIN,
			revision: [1; 32],
			generation: NonZeroU64::MIN,
		},
		PeerAddresses {
			outer: SocketAddr::from((Ipv4Addr::LOCALHOST, 12000)),
			local: Ipv4Addr::new(10, 0, 0, 1).into(),
			remote: Ipv4Addr::new(10, 0, 0, 2).into(),
		},
		StaticSecret::from([7; 32]),
		PublicKey::from(&StaticSecret::from([8; 32])),
	)
	.unwrap()
}

#[test]
fn blocked_control_admission_preserves_ordinary_protocol_reserves() {
	let mut peer = peer();
	// Exact ordinary reserves are still available to normal operations.
	peer.operations_remaining = 8;
	assert!(peer.reserve_blocked_control().is_none());
	assert_eq!(peer.operations_remaining, 8);

	peer.operations_remaining = 9;
	peer.handshakes_remaining = 1;
	assert!(peer.reserve_blocked_control().is_none());
	assert_eq!(peer.handshakes_remaining, 1);

	peer.handshakes_remaining = 2;
	assert!(peer.reserve_blocked_control().is_some());
	let mut output = [0; MAX_DATAGRAM_BYTES];
	let _ = peer.tick(&mut output).unwrap();
	assert_eq!(peer.operations_remaining, 8);
	assert!(peer.reserve_blocked_control().is_none());
}
