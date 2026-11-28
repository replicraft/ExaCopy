//! Bounded I/O for one already-connected, generation-bound WireGuard UDP peer.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use exacopy_endpoint::wireguard::{
	EmbeddedDialCommand, InnerDial, InnerDialKind, ProfileRevision, RouteObservation,
};
use tokio::net::UdpSocket;

use crate::protocol::{MAX_DATAGRAM_BYTES, PacketOutput, PeerBinding, ProtocolError, ProtocolPeer};

#[cfg(all(unix, feature = "experimental-tcp"))]
mod blocked_control;
mod error;
#[cfg(feature = "experimental-tcp")]
mod tcp;
#[cfg(feature = "experimental-tcp")]
pub use tcp::{
	TcpDialSettings, TcpRouteOwner, UdpTcpAdmission, UdpTcpDriver, UdpTcpError, UdpTcpPeer,
	UdpTcpRoute,
};
#[cfg(test)]
mod tests;

pub use error::{SocketPhase, UdpError};

/// Upper bound for one readiness wait before returning control to the caller.
pub const MAX_RECEIVE_WAIT: Duration = Duration::from_secs(1);

// Winsock reports a datagram larger than the receive buffer as WSAEMSGSIZE.
// Mio's connected recv exposes this exact native error through Tokio.
#[cfg(target_os = "windows")]
const WSAEMSGSIZE: i32 = 10040;

/// Supplies trusted route observations under the same authority that revokes them.
///
/// Serialize replacement and revocation with each synchronous callback. A
/// revocation or replacement must permanently invalidate the previous generation.
/// The actor performs its final generation check and any nonblocking send in
/// the callback. This contract concerns the application's route authority.
pub trait RouteOwner {
	/// Executes the callback once with a fresh observation while route transitions are excluded.
	fn with_observation<T>(&self, observe: impl FnOnce(RouteObservation) -> T) -> T;

	/// Atomically reserves the matching current generation once for its lifetime.
	/// Returns false on a mismatch, reuse or an unavailable generation.
	fn claim_generation(&self, binding: RouteObservation) -> bool;
}

/// Result of at most one bounded protocol or UDP operation.
#[must_use]
pub enum UdpProgress<'buffer> {
	/// A processed protocol action produced no output.
	Idle,
	/// The bounded receive did not consume a datagram.
	NoDatagram,
	/// One datagram was submitted to the exact connected socket.
	Sent,
	/// The socket did not accept the datagram. The actor retains no retry buffer.
	Backpressure,
	/// Authenticated inner packet confined by the peer policy at delivery.
	/// Later effects need their own current route check.
	Inner(&'buffer [u8]),
}

/// Owns one fixed connected UDP socket and one matching BoringTun generation.
///
/// The caller transfers exclusive ownership of an already-connected socket,
/// including exclusive control of its connected peer. Every method performs
/// bounded work in the caller's task. The first observed route loss or expiry
/// retires the generation. The owner can explicitly retire an idle actor.
pub struct UdpPeer<R> {
	owner: R,
	binding: RouteObservation,
	active: Option<Active>,
}

struct Active {
	socket: UdpSocket,
	protocol: ProtocolPeer,
}

impl<R: RouteOwner> UdpPeer<R> {
	/// Takes the socket previously connected by the trusted outer capability.
	/// # Errors
	/// Refuses a changed route, an unconnected socket, a mismatched kernel peer
	/// or an unavailable protocol generation.
	pub fn from_connected(
		owner: R,
		socket: UdpSocket,
		mut protocol: ProtocolPeer,
	) -> Result<Self, UdpError> {
		let binding = route_binding(protocol.binding());
		require_connected_peer(&socket, protocol.outer_endpoint(), SocketPhase::Admit)?;
		owner.with_observation(|current| ensure_binding(binding, current, &mut protocol))?;
		if !owner.claim_generation(binding) {
			return Err(UdpError::GenerationUnavailable);
		}
		Ok(Self {
			owner,
			binding,
			active: Some(Active { socket, protocol }),
		})
	}

	/// Starts one protocol handshake and attempts one bounded outer send.
	/// # Errors
	/// Refuses unavailable authority or reports protocol or socket failure.
	pub fn initiate<'buffer>(
		&mut self,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<UdpProgress<'buffer>, UdpError> {
		self.operate(Operation::Initiate, output)
	}

	/// Progresses one protocol timer step under the same bounded authority.
	/// # Errors
	/// Refuses unavailable authority or reports protocol or socket failure.
	pub fn tick<'buffer>(
		&mut self,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<UdpProgress<'buffer>, UdpError> {
		self.operate(Operation::Tick, output)
	}

	/// Sends one inner packet through the established, pinned peer.
	/// # Errors
	/// Refuses unavailable authority, unestablished session, invalid packet or
	/// native socket failure.
	pub fn send_inner<'buffer>(
		&mut self,
		packet: &[u8],
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<UdpProgress<'buffer>, UdpError> {
		self.operate(Operation::Send(packet), output)
	}

	/// Waits for readiness once, then processes at most one connected datagram.
	/// # Errors
	/// Refuses excessive wait, unavailable authority, invalid datagrams and
	/// native socket failure. Timeout returns `NoDatagram` after checking freshness.
	///
	/// # Panics
	/// Requires a Tokio runtime with its time driver enabled.
	pub async fn receive_one<'buffer>(
		&mut self,
		wait: Duration,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<UdpProgress<'buffer>, UdpError> {
		self.check()?;
		if wait > MAX_RECEIVE_WAIT {
			return Err(UdpError::WaitLimit);
		}
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		match tokio::time::timeout(wait, active.socket.readable()).await {
			Ok(Ok(())) => self.receive_ready(output),
			Ok(Err(error)) => {
				self.check()?;
				self.keep_active(Err(UdpError::Socket(SocketPhase::Receive, error)))
			}
			Err(_) => {
				self.check()?;
				Ok(UdpProgress::NoDatagram)
			}
		}
	}

	fn receive_ready<'buffer>(
		&mut self,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<UdpProgress<'buffer>, UdpError> {
		// Reserve one extra byte so a truncated datagram cannot pass the size check.
		let mut packet = [0; MAX_DATAGRAM_BYTES + 1];
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		let receipt = self.owner.with_observation(|current| {
			ensure_binding(self.binding, current, &mut active.protocol)?;
			require_connected_peer(
				&active.socket,
				active.protocol.outer_endpoint(),
				SocketPhase::Receive,
			)?;
			match active.socket.try_recv(&mut packet) {
				Ok(size) => Ok(Some(size)),
				Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
				#[cfg(target_os = "windows")]
				Err(error) if error.raw_os_error() == Some(WSAEMSGSIZE) => Err(UdpError::DatagramLimit),
				Err(error) => Err(UdpError::Socket(SocketPhase::Receive, error)),
			}
		});
		let Some(size) = self.keep_active(receipt)? else {
			return Ok(UdpProgress::NoDatagram);
		};
		if size > MAX_DATAGRAM_BYTES {
			return Err(UdpError::DatagramLimit);
		}
		self.operate(Operation::Receive(&packet[..size]), output)
	}

	/// Reobserves readiness on this fixed connected peer without claiming a dial.
	///
	/// The actor's bounded handshake, timer and generation policy still governs
	/// progress. Recheck after each bounded receive or timer step before consuming
	/// the actor in an inner dial. Readiness can lapse before dial admission.
	///
	/// # Errors
	/// Refuses an expired, retired, revoked or mismatched connected peer.
	pub fn session_ready(&mut self) -> Result<bool, UdpError> {
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		let result = self.owner.with_observation(|current| {
			check_current_socket(self.binding, current, active)?;
			Ok(active.protocol.has_session())
		});
		self.keep_active(result)
	}

	/// Rechecks a dispatched application dial under the actor lease.
	///
	/// The result identifies a permitted command for a future inner-stack
	/// integration. This standalone actor starts no inner sockets.
	/// # Errors
	/// Refuses stale/unavailable authority or a missing transport-key session.
	pub fn admit_inner_dial(
		&mut self,
		command: EmbeddedDialCommand,
	) -> Result<InnerDial, UdpError> {
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		let result = self.owner.with_observation(|current| {
			check_current_socket(self.binding, current, active)?;
			if !active.protocol.has_session() {
				return Err(UdpError::Protocol(ProtocolError::NoSession));
			}
			let target = command.start(current).map_err(UdpError::Dial)?;
			if target.kind() != InnerDialKind::Stream
				|| target.address().ip() != active.protocol.inner_remote()
			{
				return Err(UdpError::InnerTargetUnsupported);
			}
			Ok(target)
		});
		self.keep_active(result)
	}

	/// Drops the only actor-owned socket and all protocol state.
	pub fn retire(&mut self) {
		self.active = None;
	}

	fn check(&mut self) -> Result<(), UdpError> {
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		let result = self.owner.with_observation(|current| {
			ensure_binding(self.binding, current, &mut active.protocol)
		});
		self.keep_active(result)
	}

	fn operate<'buffer>(
		&mut self,
		operation: Operation<'_>,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<UdpProgress<'buffer>, UdpError> {
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		let result = self.owner.with_observation(|current| {
			ensure_binding(self.binding, current, &mut active.protocol)?;
			operation
				.run(&mut active.protocol, output)
				.map_err(UdpError::Protocol)
		});
		let packet = self.keep_active(result)?;
		let active = self.active.as_mut().ok_or(UdpError::Retired)?;
		let result = self.owner.with_observation(|current| {
			if let PacketOutput::Outer { destination, .. } = packet {
				if destination != active.protocol.outer_endpoint() {
					return Err(UdpError::EndpointMismatch);
				}
				require_connected_peer(&active.socket, destination, SocketPhase::Send)?;
			}
			ensure_binding(self.binding, current, &mut active.protocol)?;
			active
				.protocol
				.check_output(&packet)
				.map_err(UdpError::Protocol)?;
			match packet {
				PacketOutput::None => Ok(UdpProgress::Idle),
				PacketOutput::Inner(packet) => Ok(UdpProgress::Inner(packet)),
				PacketOutput::Outer { bytes, .. } => send_datagram(&active.socket, bytes),
			}
		});
		self.keep_active(result)
	}

	fn keep_active<T>(&mut self, result: Result<T, UdpError>) -> Result<T, UdpError> {
		if result.as_ref().is_err_and(|error| error.retires_peer()) {
			self.retire();
		}
		result
	}
}

enum Operation<'packet> {
	Initiate,
	Tick,
	Send(&'packet [u8]),
	Receive(&'packet [u8]),
	#[cfg(all(unix, feature = "experimental-tcp"))]
	ReceiveBlocked(
		crate::protocol::blocked_control::BlockedControlPermit,
		&'packet [u8],
	),
}

impl Operation<'_> {
	fn run<'buffer>(
		self,
		protocol: &mut ProtocolPeer,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		match self {
			Self::Initiate => protocol.initiate(output),
			Self::Tick => protocol.tick(output),
			Self::Send(packet) => protocol.send(packet, output),
			Self::Receive(packet) => protocol.receive(protocol.outer_endpoint(), packet, output),
			#[cfg(all(unix, feature = "experimental-tcp"))]
			Self::ReceiveBlocked(permit, packet) => protocol.receive_blocked_control(permit, packet, output),
		}
	}
}

fn check_current_socket(
	expected: RouteObservation,
	current: RouteObservation,
	active: &mut Active,
) -> Result<(), UdpError> {
	ensure_binding(expected, current, &mut active.protocol)?;
	require_connected_peer(
		&active.socket,
		active.protocol.outer_endpoint(),
		SocketPhase::Admit,
	)
}

fn route_binding(binding: PeerBinding) -> RouteObservation {
	RouteObservation::EmbeddedWireGuard {
		instance: binding.actor,
		revision: ProfileRevision::from_bytes(binding.revision),
		generation: binding.generation,
	}
}

fn ensure_binding(
	expected: RouteObservation,
	current: RouteObservation,
	protocol: &mut ProtocolPeer,
) -> Result<(), UdpError> {
	if expected != current {
		return Err(UdpError::RouteChanged);
	}
	protocol.check_generation().map_err(UdpError::Protocol)
}

fn require_connected_peer(
	socket: &UdpSocket,
	expected: SocketAddr,
	phase: SocketPhase,
) -> Result<(), UdpError> {
	let current = socket
		.peer_addr()
		.map_err(|error| UdpError::Socket(phase, error))?;
	if current != expected {
		return Err(UdpError::EndpointMismatch);
	}
	Ok(())
}

fn send_datagram<'buffer>(
	socket: &UdpSocket,
	bytes: &[u8],
) -> Result<UdpProgress<'buffer>, UdpError> {
	match socket.try_send(bytes) {
		Ok(written) if written == bytes.len() => Ok(UdpProgress::Sent),
		Ok(_) => Err(UdpError::Socket(
			SocketPhase::Send,
			io::Error::from(io::ErrorKind::WriteZero),
		)),
		Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(UdpProgress::Backpressure),
		Err(error) => Err(UdpError::Socket(SocketPhase::Send, error)),
	}
}
