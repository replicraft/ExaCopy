//! Non-consuming FIFO-head inspection under the connected socket owner's lease.

use std::io::ErrorKind;

use crate::protocol::blocked_control::{BlockedControlPermit, is_control};

use super::{
	MAX_DATAGRAM_BYTES, Operation, ProtocolError, RouteOwner, SocketPhase, UdpError, UdpPeer,
	UdpProgress, check_current_socket,
};

pub(super) enum ControlRead {
	Continue,
	Park,
}

enum Head {
	Continue,
	Park,
	Control(usize, BlockedControlPermit),
}

impl<R: RouteOwner> UdpPeer<R> {
	pub(super) fn blocked_control_available(&self) -> bool {
		self.active
			.as_ref()
			.is_some_and(|active| active.protocol.blocked_control_available())
	}

	pub(super) fn receive_blocked_control(
		&mut self,
		output: &mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<ControlRead, UdpError> {
		let mut datagram = [0; MAX_DATAGRAM_BYTES + 1];
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		let inspected = self.owner.with_observation(|current| {
			check_current_socket(self.binding, current, active)?;
			if !active.protocol.blocked_control_available() {
				return Ok(Head::Park);
			}

			let length = match active.socket.try_peek(&mut datagram) {
				Ok(length) if is_control(&datagram[..length]) => length,
				Ok(_) => return Ok(Head::Park),
				Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(Head::Continue),
				Err(error) => return Err(UdpError::Socket(SocketPhase::Receive, error)),
			};
			// The actor owns the only reader. Leave a data head queued, and
			// charge the allowance before dequeue or cryptographic work.
			let Some(permit) = active.protocol.reserve_blocked_control() else {
				return Ok(Head::Park);
			};
			match active.socket.try_recv(&mut datagram) {
				Ok(count) if count == length && is_control(&datagram[..count]) => {
					Ok(Head::Control(count, permit))
				}
				Ok(_) => Err(UdpError::Protocol(ProtocolError::InvalidInnerPacket)),
				Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(Head::Continue),
				Err(error) => Err(UdpError::Socket(SocketPhase::Receive, error)),
			}
		});
		let (count, permit) = match self.keep_active(inspected)? {
			Head::Continue => return Ok(ControlRead::Continue),
			Head::Park => return Ok(ControlRead::Park),
			Head::Control(count, permit) => (count, permit),
		};
		match self.operate(
			Operation::ReceiveBlocked(permit, &datagram[..count]),
			output,
		)? {
			UdpProgress::Idle | UdpProgress::Sent | UdpProgress::Backpressure => {
				Ok(ControlRead::Continue)
			}
			UdpProgress::Inner(_) | UdpProgress::NoDatagram => {
				Err(UdpError::Protocol(ProtocolError::InvalidInnerPacket))
			}
		}
	}
}
