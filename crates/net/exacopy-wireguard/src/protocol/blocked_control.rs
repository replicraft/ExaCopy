//! Bounded speculative receive while the inner TCP ingress slot is occupied.

use boringtun::noise::{Packet, Tunn};

use super::{
	MAX_DATAGRAM_BYTES, PacketOutput, ProtocolError, ProtocolPeer, ReceiveMode, TRANSPORT_OVERHEAD,
};

// A separate allowance bounds extra receives while TCP cannot accept data.
// Keep ordinary operation and handshake work available after this lane parks.
const BLOCKED_CONTROL_LIMIT: u8 = 8;
const ORDINARY_OPERATION_RESERVE: u32 = 8;
const ORDINARY_HANDSHAKE_RESERVE: u16 = 1;

pub(super) struct BlockedControls(u8);

impl BlockedControls {
	pub(super) const fn new() -> Self {
		Self(BLOCKED_CONTROL_LIMIT)
	}

	pub(super) fn renew(&mut self) {
		*self = Self::new();
	}
}

/// Fresh charge owned by the same synchronous receive step.
pub(crate) struct BlockedControlPermit(());

impl ProtocolPeer {
	#[cfg(test)]
	pub(crate) const fn blocked_control_allowance_for_test(&self) -> u8 {
		self.blocked_controls.0
	}

	pub(crate) const fn blocked_control_available(&self) -> bool {
		self.blocked_controls.0 != 0
			&& self.operations_remaining > ORDINARY_OPERATION_RESERVE
			&& self.handshakes_remaining > ORDINARY_HANDSHAKE_RESERVE
	}

	pub(crate) fn reserve_blocked_control(&mut self) -> Option<BlockedControlPermit> {
		if !self.blocked_control_available() {
			return None;
		}
		self.blocked_controls.0 -= 1;
		Some(BlockedControlPermit(()))
	}

	pub(crate) fn receive_blocked_control<'buffer>(
		&mut self,
		_permit: BlockedControlPermit,
		packet: &[u8],
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		self.receive_datagram(
			self.outer_endpoint(),
			packet,
			output,
			ReceiveMode::BlockedControl,
		)
	}
}

/// Classifies only shapes that cannot carry inner data. The ordinary protocol
/// path still authenticates the input and checks current transport-key use.
pub(crate) fn is_control(datagram: &[u8]) -> bool {
	match Tunn::parse_incoming_packet(datagram) {
		Ok(
			Packet::HandshakeInit(_) | Packet::HandshakeResponse(_) | Packet::PacketCookieReply(_),
		) => true,
		Ok(Packet::PacketData(_)) => datagram.len() == TRANSPORT_OVERHEAD,
		Err(_) => false,
	}
}

#[cfg(test)]
mod tests;
