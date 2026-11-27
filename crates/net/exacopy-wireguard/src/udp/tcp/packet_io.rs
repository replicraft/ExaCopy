use std::io;
use std::time::Duration;

use tokio::time::{Instant, sleep_until};

use crate::protocol::{INNER_MTU, MAX_DATAGRAM_BYTES, PeerBinding};
use crate::stack::{PacketDisposition, PacketEvent, PacketInterest, PacketIo};
#[cfg(unix)]
use crate::udp::blocked_control::ControlRead;
use crate::udp::{RouteOwner, SocketPhase, UdpError, UdpPeer, UdpProgress};

use super::UdpTcpError;

const PROTOCOL_TICK: Duration = Duration::from_millis(250);
const READINESS_WORK_BUDGET: usize = 8;

pub(super) struct UdpPacketIo<R> {
	peer: UdpPeer<R>,
	binding: PeerBinding,
	scratch: [u8; MAX_DATAGRAM_BYTES],
	next_tick: Instant,
	write_ready: bool,
}

impl<R: RouteOwner> UdpPacketIo<R> {
	pub(super) fn new(peer: UdpPeer<R>, binding: PeerBinding) -> Result<Self, UdpError> {
		if peer
			.active
			.as_ref()
			.ok_or(UdpError::Retired)?
			.protocol
			.binding()
			!= binding
		{
			return Err(UdpError::RouteChanged);
		}
		Ok(Self {
			peer,
			binding,
			scratch: [0; MAX_DATAGRAM_BYTES],
			next_tick: Instant::now(),
			write_ready: false,
		})
	}

	fn check_binding(&mut self, binding: PeerBinding) -> Result<(), UdpError> {
		if binding != self.binding {
			self.peer.retire();
			return Err(UdpError::RouteChanged);
		}
		self.peer.check()
	}

	fn tick_if_due(&mut self) -> Result<(), UdpTcpError> {
		let now = Instant::now();
		if now < self.next_tick {
			return Ok(());
		}
		self.next_tick = now.checked_add(PROTOCOL_TICK).ok_or(UdpTcpError::Clock)?;
		match self.peer.tick(&mut self.scratch)? {
			UdpProgress::Idle | UdpProgress::Sent | UdpProgress::Backpressure => Ok(()),
			_ => Err(UdpTcpError::Output),
		}
	}
}

#[cfg(all(test, unix))]
#[path = "tests/control.rs"]
mod control_tests;

enum Ready {
	Read(io::Result<()>),
	Write(io::Result<()>),
	Tick,
}

impl<R: RouteOwner + Send> PacketIo for UdpPacketIo<R> {
	type Error = UdpTcpError;

	fn check(&mut self, binding: PeerBinding) -> Result<(), Self::Error> {
		self.check_binding(binding)?;
		self.tick_if_due()
	}

	fn send(
		&mut self,
		binding: PeerBinding,
		packet: &[u8],
	) -> Result<PacketDisposition, Self::Error> {
		self.check_binding(binding)?;
		if !std::mem::take(&mut self.write_ready) {
			return Ok(PacketDisposition::Backpressure);
		}
		// The actor rechecks this same generation under its owner immediately
		// before try_send. No ciphertext is retained across a readiness wait.
		match self.peer.send_inner(packet, &mut self.scratch)? {
			UdpProgress::Sent => Ok(PacketDisposition::Accepted),
			UdpProgress::Backpressure => Ok(PacketDisposition::Backpressure),
			_ => Err(UdpTcpError::Output),
		}
	}

	async fn wait(
		&mut self,
		interest: PacketInterest,
		packet: &mut [u8; INNER_MTU],
	) -> Result<PacketEvent, Self::Error> {
		let mut work = 0;
		#[cfg(unix)]
		let mut control_parked = false;
		loop {
			if work == READINESS_WORK_BUDGET {
				tokio::task::yield_now().await;
				work = 0;
				continue;
			}
			work += 1;
			self.check(self.binding)?;
			let read = interest.receive;
			#[cfg(unix)]
			let read = read || (!control_parked && self.peer.blocked_control_available());
			let socket = &self.peer.active.as_ref().ok_or(UdpError::Retired)?.socket;
			let ready = tokio::select! {
				result = socket.readable(), if read => Ready::Read(result),
				result = socket.writable(), if interest.writable => Ready::Write(result),
				() = sleep_until(self.next_tick) => Ready::Tick,
			};
			match ready {
				#[cfg(unix)]
				Ready::Read(Ok(())) if !interest.receive => {
					control_parked = matches!(
						self.peer.receive_blocked_control(&mut self.scratch)?,
						ControlRead::Park
					);
				}
				Ready::Read(Ok(())) => {
					if let UdpProgress::Inner(bytes) = self.peer.receive_ready(&mut self.scratch)? {
						let output = packet.get_mut(..bytes.len()).ok_or(UdpTcpError::Output)?;
						output.copy_from_slice(bytes);
						return Ok(PacketEvent::Received(output.len()));
					}
				}
				Ready::Write(Ok(())) => {
					self.check_binding(self.binding)?;
					self.write_ready = true;
					return Ok(PacketEvent::Writable);
				}
				Ready::Read(Err(error)) => {
					self.peer.retire();
					return Err(UdpError::Socket(SocketPhase::Receive, error).into());
				}
				Ready::Write(Err(error)) => {
					self.peer.retire();
					return Err(UdpError::Socket(SocketPhase::Send, error).into());
				}
				Ready::Tick => {}
			}
		}
	}
}
