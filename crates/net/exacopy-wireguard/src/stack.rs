//! Single-flow, caller-driven inner TCP for an approved embedded route.
//!
//! This experimental adapter owns no host sockets. The route owner must
//! serialize authorization, flow activity, authenticated packet delivery,
//! and egress with revocation of the current WireGuard generation.

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, Route, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::tcp::{CongestionControl, RecvError, Socket, SocketBuffer, State};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpCidr};

use crate::protocol::PeerBinding;

use self::ack::EmittedSequence;
use self::device::PacketDevice;
use self::mtu::{IPV4_INNER_MIN, IPV6_INNER_MIN};

pub use self::mtu::InnerMtu;
pub use self::pump::{
	InnerTcpStream, PacketEvent, PacketInterest, PacketIo, PumpError, RouteRevocation, TcpPump,
};

#[cfg(feature = "experimental-udp")]
pub(crate) use self::pump::TcpFlowStatus;

mod ack;
mod device;
mod mtu;
mod packet;
mod pump;
#[cfg(test)]
pub(crate) mod tests;

const STREAM_BUFFER_BYTES: usize = 32 * 1024;
// A due-now hint without work must not cause unlimited same-tick polling.
const MIN_TIMER_DELAY: Duration = Duration::from_millis(1);

/// One exact TCP flow approved by the route owner.
pub struct TcpFlow {
	/// Binding of the owning WireGuard route generation.
	pub binding: PeerBinding,
	/// Configured inner client address and a fresh ephemeral port.
	pub local: SocketAddr,
	/// Exact inner SSH service address and port from the consumed dial.
	pub remote: SocketAddr,
	/// Packet budget derived from the selected outer path.
	pub mtu: InnerMtu,
}

/// A bounded TCP stream and one packet slot in each direction.
pub struct InnerTcp {
	flow: TcpFlow,
	live: Option<LiveTcp>,
}

struct LiveTcp {
	clock: Duration,
	device: PacketDevice,
	interface: Interface,
	sockets: SocketSet<'static>,
	handle: SocketHandle,
	emitted: EmittedSequence,
	pending_frontier: Option<u32>,
	pending_reset: bool,
}

/// Current connection state for the owning actor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpState {
	/// The TCP handshake is pending.
	Opening,
	/// The stream has an established send half.
	Writable,
	/// The local send half is closing or closed.
	Closing,
	/// The underlying socket or route is closed.
	Closed,
}

/// Read progress independent of send readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadProgress {
	/// The receive buffer supplied these bytes.
	Bytes(NonZeroUsize),
	/// Receive is open or still connecting and there are no readable bytes.
	Pending,
	/// The peer performed a TCP half-close and no buffered bytes remain.
	Eof,
}

/// The scheduler action following a bounded TCP poll.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollHint {
	/// Attempt authenticated egress before polling again.
	Egress,
	/// Poll by the indicated time on the caller's elapsed clock.
	At(Duration),
	/// Poll on incoming packets or application activity.
	OnActivity,
}

/// The route owner's decision about one offered inner packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDisposition {
	/// The packet was submitted under the current matching route lease.
	/// Readiness, encryption or a queue reservation alone does not qualify.
	Accepted,
	/// Keep the packet queued until the route owner can accept it.
	Backpressure,
}

/// Inner TCP connection, packet, clock or flow failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TcpError {
	/// The address pair or port is outside the fixed-flow profile.
	InvalidFlow,
	/// The outer path cannot carry the selected inner IP profile.
	Mtu,
	/// The stack could not start the configured TCP connection.
	Connect,
	/// The clock moved backwards or exceeded the profile's range.
	Clock,
	/// A packet failed the bounded IP/TCP profile or checksum.
	Packet,
	/// A packet's address or port is outside the selected tuple.
	FlowMismatch,
	/// The revocation signal belongs to a different route generation.
	RouteMismatch,
	/// A reset accepted by the TCP stack closed the connection.
	Reset,
	/// The peer acknowledges beyond the highest emitted TCP sequence.
	Acknowledgement,
	/// Egress tried to advance an inconsistent TCP sequence frontier.
	Sequence,
	/// The one-packet ingress queue is already occupied.
	IngressFull,
	/// The caller provided an empty application receive buffer.
	EmptyRead,
	/// The flow is closed, fenced, interrupted or unable to send.
	Closed,
}

impl fmt::Display for TcpError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::InvalidFlow => "invalid inner TCP address pair or port",
			Self::Mtu => "outer path MTU cannot carry the selected inner profile",
			Self::Connect => "could not start the selected inner TCP flow",
			Self::Clock => "inner TCP clock observation is invalid",
			Self::Packet => "inner packet is outside the TCP packet profile",
			Self::FlowMismatch => "inner packet is outside the authorized TCP tuple",
			Self::RouteMismatch => "inner TCP route revocation is bound to another generation",
			Self::Reset => "the peer reset the inner TCP connection",
			Self::Acknowledgement => "peer acknowledged un-emitted TCP sequence space",
			Self::Sequence => "invalid inner TCP egress sequence",
			Self::IngressFull => "inner TCP ingress slot is full",
			Self::EmptyRead => "inner TCP receive buffer is empty",
			Self::Closed => "inner TCP flow is closed",
		})
	}
}

impl std::error::Error for TcpError {}

impl InnerTcp {
	/// Starts an active open after the route owner consumed its dial permit.
	///
	/// The caller supplies unpredictable entropy for the TCP sequence space.
	/// The elapsed clock starts at zero for this flow. The caller owns its
	/// deadlines and must fence the flow whenever route authority is lost.
	///
	/// # Errors
	/// Refuses invalid address pairs, zero ports or an unavailable stack.
	pub fn connect(flow: TcpFlow, random_seed: u64) -> Result<Self, TcpError> {
		let mut live = LiveTcp::new(&flow, random_seed)?;
		live.sockets
			.get_mut::<Socket<'_>>(live.handle)
			.connect(live.interface.context(), flow.remote, flow.local)
			.map_err(|_| TcpError::Connect)?;
		Ok(Self {
			flow,
			live: Some(live),
		})
	}

	/// Returns the binding to compare with the owner's current route.
	#[must_use]
	pub const fn binding(&self) -> PeerBinding {
		self.flow.binding
	}

	/// Queues one authenticated inner packet for the exact reverse tuple.
	///
	/// # Errors
	/// Refuses a closed flow, unsupported packet or occupied ingress slot.
	pub fn ingress(&mut self, bytes: &[u8]) -> Result<(), TcpError> {
		let live = self.live.as_mut().ok_or(TcpError::Closed)?;
		if live.socket().state() == State::Closed {
			return Err(TcpError::Closed);
		}
		let packet = packet::parse(
			bytes,
			self.flow.remote,
			self.flow.local,
			self.flow.mtu.bytes(),
		)?;
		live.emitted.admit(&packet.segment)?;
		if live.device.rx.get().is_some() {
			return Err(TcpError::IngressFull);
		}
		live.device.rx.queue(bytes);
		live.pending_reset = packet.reset;
		Ok(())
	}

	/// Advances one bounded ingress and egress step on the supplied clock.
	///
	/// # Errors
	/// Fences on an accepted reset, an invalid clock or unexpected stack output.
	pub fn poll(&mut self, elapsed: Duration) -> Result<PollHint, TcpError> {
		let result = self.poll_live(elapsed);
		if result.is_err() {
			self.fence();
		}
		result
	}

	fn poll_live(&mut self, elapsed: Duration) -> Result<PollHint, TcpError> {
		let live = self.live.as_mut().ok_or(TcpError::Closed)?;
		if elapsed < live.clock {
			return Err(TcpError::Clock);
		}
		let millis = u32::try_from(elapsed.as_millis()).map_err(|_| TcpError::Clock)?;
		let timestamp = Instant::from_millis(i64::from(millis));
		live.clock = elapsed;
		if live.device.tx.get().is_none() {
			let was_open = live.socket().state() != State::Closed;
			live.interface
				.poll_ingress_single(timestamp, &mut live.device, &mut live.sockets);
			if live.device.rx.get().is_none()
				&& std::mem::take(&mut live.pending_reset)
				&& was_open
				&& live.socket().state() == State::Closed
			{
				return Err(TcpError::Reset);
			}
			live.interface
				.poll_egress(timestamp, &mut live.device, &mut live.sockets);
		}
		if let Some(bytes) = live.device.tx.get() {
			let segment = packet::parse(
				bytes,
				self.flow.local,
				self.flow.remote,
				self.flow.mtu.bytes(),
			)?;
			live.pending_frontier = live.emitted.outgoing(segment.segment)?;
			return Ok(PollHint::Egress);
		}
		Ok(match live.interface.poll_delay(timestamp, &live.sockets) {
			Some(delay) => {
				let delay = Duration::from_millis(delay.total_millis()).max(MIN_TIMER_DELAY);
				PollHint::At(elapsed.checked_add(delay).ok_or(TcpError::Clock)?)
			}
			None => PollHint::OnActivity,
		})
	}

	/// Offers one pending packet to the route owner without transferring ownership.
	///
	/// The callback receives this flow's exact binding and rechecks its current
	/// lease at actual submission. On rejection or backpressure the packet
	/// stays queued. After observed revocation, the caller must fence and
	/// drop the generation.
	///
	/// # Errors
	/// Returns the callback's error without removing the packet.
	pub fn egress<E>(
		&mut self,
		send: impl FnOnce(PeerBinding, &[u8]) -> Result<PacketDisposition, E>,
	) -> Result<Option<PacketDisposition>, E> {
		let Some(live) = self.live.as_mut() else {
			return Ok(None);
		};
		let Some(bytes) = live.device.tx.get() else {
			return Ok(None);
		};
		let disposition = send(self.flow.binding, bytes)?;
		if disposition == PacketDisposition::Accepted {
			live.emitted.emitted(live.pending_frontier.take());
			live.device.tx.clear();
		}
		Ok(Some(disposition))
	}

	/// Reads the current socket state to distinguish connection loss and waiting.
	#[must_use]
	pub fn state(&self) -> TcpState {
		let Some(live) = &self.live else {
			return TcpState::Closed;
		};
		let state = live.socket().state();
		match state {
			State::Closed => TcpState::Closed,
			State::Listen | State::SynSent | State::SynReceived => TcpState::Opening,
			State::Established | State::CloseWait => TcpState::Writable,
			_ => TcpState::Closing,
		}
	}

	/// Copies bytes into the bounded transmit queue and returns the accepted count.
	///
	/// A return of zero means the queue is full, the connection is still
	/// opening, or the input is empty. Acceptance only describes local buffering.
	///
	/// # Errors
	/// Refuses writes after the send half has closed or the flow is fenced.
	pub fn write(&mut self, bytes: &[u8]) -> Result<usize, TcpError> {
		let socket = self.socket_mut()?;
		if opening(socket.state()) {
			return Ok(0);
		}
		socket.send_slice(bytes).map_err(|_| TcpError::Closed)
	}

	/// Reads into caller storage and distinguishes pending, EOF and flow loss.
	///
	/// # Errors
	/// Refuses empty buffers and ungraceful closure.
	pub fn read(&mut self, output: &mut [u8]) -> Result<ReadProgress, TcpError> {
		if output.is_empty() {
			return Err(TcpError::EmptyRead);
		}
		let socket = self.socket_mut()?;
		if opening(socket.state()) {
			return Ok(ReadProgress::Pending);
		}
		match socket.recv_slice(output) {
			Ok(length) => {
				Ok(NonZeroUsize::new(length).map_or(ReadProgress::Pending, ReadProgress::Bytes))
			}
			Err(RecvError::Finished) => Ok(ReadProgress::Eof),
			Err(RecvError::InvalidState) => Err(TcpError::Closed),
		}
	}

	/// Starts a graceful send half-close, preserving already queued bytes.
	///
	/// # Errors
	/// Refuses an opening, closed or fenced flow.
	pub fn close_send(&mut self) -> Result<(), TcpError> {
		let socket = self.socket_mut()?;
		if !socket.may_send() {
			return Err(TcpError::Closed);
		}
		socket.close();
		Ok(())
	}

	/// Discards queued packets and all TCP state without emitting traffic.
	pub fn fence(&mut self) {
		self.live = None;
	}

	fn accepts_ingress(&self) -> bool {
		self.live.as_ref().is_some_and(|live| {
			live.socket().state() != State::Closed && live.device.rx.get().is_none()
		})
	}

	fn in_time_wait(&self) -> bool {
		self.live
			.as_ref()
			.is_some_and(|live| live.socket().state() == State::TimeWait)
	}

	fn finished(&self) -> bool {
		self.live.as_ref().is_some_and(|live| {
			live.socket().state() == State::Closed && live.device.tx.get().is_none()
		})
	}

	fn socket_mut(&mut self) -> Result<&mut Socket<'static>, TcpError> {
		let live = self.live.as_mut().ok_or(TcpError::Closed)?;
		Ok(live.sockets.get_mut::<Socket<'_>>(live.handle))
	}
}

impl LiveTcp {
	fn new(flow: &TcpFlow, random_seed: u64) -> Result<Self, TcpError> {
		if !valid_endpoint(flow.local)
			|| !valid_endpoint(flow.remote)
			|| flow.local.ip() == flow.remote.ip()
			|| flow.local.is_ipv4() != flow.remote.is_ipv4()
		{
			return Err(TcpError::InvalidFlow);
		}
		let minimum = if flow.local.is_ipv4() {
			IPV4_INNER_MIN
		} else {
			IPV6_INNER_MIN
		};
		if flow.mtu.bytes() < minimum {
			return Err(TcpError::Mtu);
		}
		let mut device = PacketDevice::new(flow.mtu.bytes());
		let mut config = Config::new(HardwareAddress::Ip);
		config.random_seed = random_seed;
		let mut interface = Interface::new(config, &mut device, Instant::ZERO);
		let prefix = if flow.local.is_ipv4() { 32 } else { 128 };
		let local = IpCidr::new(flow.local.ip().into(), prefix);
		let remote = flow.remote.ip().into();
		let mut address_added = false;
		interface.update_ip_addrs(|addresses| address_added = addresses.push(local).is_ok());
		if !address_added {
			return Err(TcpError::Connect);
		}
		let route = Route {
			cidr: IpCidr::new(remote, prefix),
			via_router: remote,
			preferred_until: None,
			expires_at: None,
		};
		let mut route_added = false;
		interface
			.routes_mut()
			.update(|routes| route_added = routes.push(route).is_ok());
		if !route_added {
			return Err(TcpError::Connect);
		}

		let mut sockets = SocketSet::new(vec![SocketStorage::EMPTY]);
		let mut socket = Socket::new(
			SocketBuffer::new(vec![0; STREAM_BUFFER_BYTES]),
			SocketBuffer::new(vec![0; STREAM_BUFFER_BYTES]),
		);
		socket.set_congestion_control(CongestionControl::Reno);
		let handle = sockets.add(socket);
		Ok(Self {
			clock: Duration::ZERO,
			device,
			interface,
			sockets,
			handle,
			emitted: EmittedSequence::default(),
			pending_frontier: None,
			pending_reset: false,
		})
	}

	fn socket(&self) -> &Socket<'static> {
		self.sockets.get::<Socket<'_>>(self.handle)
	}
}

fn valid_endpoint(address: SocketAddr) -> bool {
	if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
		return false;
	}
	match address {
		SocketAddr::V4(v4) => !v4.ip().is_broadcast(),
		SocketAddr::V6(v6) => {
			v6.scope_id() == 0 && v6.flowinfo() == 0 && v6.ip().to_ipv4_mapped().is_none()
		}
	}
}

fn opening(state: State) -> bool {
	matches!(state, State::Listen | State::SynSent | State::SynReceived)
}
