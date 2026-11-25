//! One fixed WireGuard peer with caller-owned packet buffers and no socket API.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU64, NonZeroU128};

use boringtun::noise::{Tunn, TunnResult};
pub use boringtun::x25519::{PublicKey, StaticSecret};

mod clock;
mod packet;
#[cfg(test)]
mod tests;

use clock::GenerationClock;
use packet::{addresses, admitted_counter, is_literal_unicast};

/// Maximum inner packet size in this fixed-MTU experimental profile.
pub const INNER_MTU: usize = 1420;
const PADDING_ALIGNMENT: usize = 16;
const TRANSPORT_OVERHEAD: usize = 32;
/// Maximum encrypted datagram, including peer padding and transport overhead.
pub const MAX_DATAGRAM_BYTES: usize =
	INNER_MTU.next_multiple_of(PADDING_ALIGNMENT) + TRANSPORT_OVERHEAD;
const SINGLE_PEER_INDEX: u32 = 1;
// One operation produces at most one transport message in Tunn 0.7.1. Count
// control operations too because the handshake and timer paths can emit keepalives.
const MAX_GENERATION_OPERATIONS: u32 = 1 << 20;

/// Route-owner binding carried with protocol status to its owning actor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerBinding {
	/// Digest of the independently approved profile revision.
	pub revision: [u8; 32],
	/// Actor identity assigned by the trusted route coordinator.
	pub actor: NonZeroU128,
	/// The connection generation owned by the actor.
	pub generation: NonZeroU64,
}

/// A factual observation of the local BoringTun key session.
/// It supplies no evidence about sockets, DNS, route confinement or SSH identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SessionObservation {
	/// The binding carried by this peer instance.
	pub binding: PeerBinding,
	/// Whether BoringTun currently has an active transport-key slot.
	pub has_session: bool,
}

/// One authenticated peer on a fixed outer endpoint and a pair of inner addresses.
#[derive(Clone, Copy)]
pub struct PeerAddresses {
	/// Exact approved outer datagram destination and receive origin.
	pub outer: SocketAddr,
	/// Inner local address assigned to this peer's stack.
	pub local: IpAddr,
	/// Inner address belonging to this peer.
	pub remote: IpAddr,
}

/// A single protocol result. Buffers expire on the caller's next reuse.
#[must_use]
pub enum PacketOutput<'buffer> {
	/// No packet to forward.
	None,
	/// One WireGuard datagram destined for the only authorized outer endpoint.
	Outer {
		/// Exact fixed destination address and port.
		destination: SocketAddr,
		/// Ciphertext or a WireGuard control packet.
		bytes: &'buffer [u8],
	},
	/// One authenticated inner IP packet after exact source and destination checks.
	Inner(&'buffer [u8]),
}

/// Owns BoringTun protocol state for exactly one fixed peer.
/// The caller drives timer progress and provides trusted route and key inputs.
/// The experimental generation expires 120 seconds after construction and has
/// a fixed operation budget. The deadline uses the same monotonic clock as
/// BoringTun, with a margin below its 180-second key rejection age. The owner
/// creates a new generation when a limit is reached.
/// Ownership of this value alone conveys no I/O or runtime qualification.
pub struct ProtocolPeer {
	binding: PeerBinding,
	endpoints: PeerAddresses,
	tunnel: Tunn,
	clock: GenerationClock,
	operations_remaining: u32,
}

impl ProtocolPeer {
	/// Creates a disconnected protocol peer from independently reviewed inputs.
	/// # Errors
	/// Refuses ambiguous addresses, a zero local key, identical static public keys and an invalid
	/// configured key agreement. This initial profile has no PSK or keepalive setting.
	pub fn new(
		binding: PeerBinding,
		endpoints: PeerAddresses,
		local_private: StaticSecret,
		remote_public: PublicKey,
	) -> Result<Self, ProtocolError> {
		if endpoints.outer.port() == 0
			|| !is_literal_unicast(endpoints.outer.ip())
			|| matches!(endpoints.outer, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
			|| endpoints.local == endpoints.remote
			|| endpoints.local.is_ipv4() != endpoints.remote.is_ipv4()
			|| !is_literal_unicast(endpoints.local)
			|| !is_literal_unicast(endpoints.remote)
		{
			return Err(ProtocolError::InvalidAddresses);
		}
		if local_private.as_bytes() == &[0; 32]
			|| PublicKey::from(&local_private) == remote_public
			|| !local_private
				.diffie_hellman(&remote_public)
				.was_contributory()
		{
			return Err(ProtocolError::InvalidPeerKey);
		}
		let clock = GenerationClock::start()?;
		let tunnel = Tunn::new(
			local_private,
			remote_public,
			None,
			None,
			SINGLE_PEER_INDEX,
			None,
		);
		Ok(Self {
			binding,
			endpoints,
			tunnel,
			clock,
			operations_remaining: MAX_GENERATION_OPERATIONS,
		})
	}

	/// Returns the current key-slot observation for this actor and generation.
	#[must_use]
	pub fn observation(&self) -> SessionObservation {
		SessionObservation {
			binding: self.binding,
			has_session: self.require_active().is_ok()
				&& self.tunnel.time_since_last_handshake().is_some(),
		}
	}

	/// Starts a BoringTun handshake without submitting a pre-handshake payload.
	/// # Errors
	/// Reports a rejected protocol operation.
	pub fn initiate<'buffer>(
		&mut self,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		self.reserve_operation()?;
		let result = self.tunnel.format_handshake_initiation(output, false);
		self.translate(result)
	}

	/// Progresses retransmit, rekey and expiry timers owned by BoringTun.
	/// BoringTun may queue an empty keepalive when no current slot exists. This
	/// adapter never drains that queue and never submits pre-handshake payloads.
	/// # Errors
	/// Reports expiry or a rejected protocol operation.
	pub fn tick<'buffer>(
		&mut self,
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		self.reserve_operation()?;
		let result = self.tunnel.update_timers(output);
		self.translate(result)
	}

	/// Processes one bounded datagram from the one approved outer endpoint.
	/// A returned control packet does not establish a fresh peer observation.
	/// # Errors
	/// Refuses foreign senders, invalid datagrams, failed authentication and
	/// decrypted packets outside the approved inner address pair.
	pub fn receive<'buffer>(
		&mut self,
		sender: SocketAddr,
		datagram: &[u8],
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		if sender != self.endpoints.outer {
			return Err(ProtocolError::OuterEndpoint);
		}
		if datagram.is_empty() || datagram.len() > MAX_DATAGRAM_BYTES {
			return Err(ProtocolError::PacketBounds);
		}
		if !admitted_counter(datagram) {
			return Err(ProtocolError::CounterLimit);
		}
		self.reserve_operation()?;
		let result = self.tunnel.decapsulate(Some(sender.ip()), datagram, output);
		self.translate(result)
	}

	/// Encrypts exactly one bounded, address-confined inner packet.
	/// # Errors
	/// Refuses unsupported packets and sends without a current transport-key slot.
	/// The latter refusal keeps pending payloads out of BoringTun's per-peer queue.
	pub fn send<'buffer>(
		&mut self,
		packet: &[u8],
		output: &'buffer mut [u8; MAX_DATAGRAM_BYTES],
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		self.require_active()?;
		if self.tunnel.time_since_last_handshake().is_none() {
			return Err(ProtocolError::NoSession);
		}
		self.check_inner(packet, self.endpoints.local, self.endpoints.remote)?;
		self.reserve_operation()?;
		// This is the exact slot test used by BoringTun 0.7.1's encapsulate.
		// No operation can mutate the tunnel between the check and this call.
		let result = self.tunnel.encapsulate(packet, output);
		self.translate(result)
	}

	fn require_active(&self) -> Result<(), ProtocolError> {
		self.require_available()?;
		self.clock.check()
	}

	fn require_available(&self) -> Result<(), ProtocolError> {
		if self.tunnel.is_expired() {
			return Err(ProtocolError::Expired);
		}
		if self.operations_remaining == 0 {
			return Err(ProtocolError::OperationLimit);
		}
		Ok(())
	}

	fn reserve_operation(&mut self) -> Result<(), ProtocolError> {
		self.require_available()?;
		self.clock.advance()?;
		self.operations_remaining -= 1;
		Ok(())
	}

	fn translate<'buffer>(
		&mut self,
		result: TunnResult<'buffer>,
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		if self.tunnel.is_expired() {
			return Err(ProtocolError::Expired);
		}
		self.clock.advance()?;
		match result {
			TunnResult::Done => Ok(PacketOutput::None),
			TunnResult::Err(_) => Err(ProtocolError::Rejected),
			TunnResult::WriteToNetwork(bytes) => Ok(PacketOutput::Outer {
				destination: self.endpoints.outer,
				bytes,
			}),
			TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
				self.check_inner(bytes, self.endpoints.remote, self.endpoints.local)?;
				Ok(PacketOutput::Inner(bytes))
			}
		}
	}

	fn check_inner(
		&self,
		packet: &[u8],
		source: IpAddr,
		destination: IpAddr,
	) -> Result<(), ProtocolError> {
		if packet.is_empty() || packet.len() > INNER_MTU {
			return Err(ProtocolError::PacketBounds);
		}
		let observation = addresses(packet).ok_or(ProtocolError::InvalidInnerPacket)?;
		if observation != (source, destination) {
			return Err(ProtocolError::InnerScope);
		}
		Ok(())
	}
}

/// Redacted failures for the experimental fixed-peer adapter.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtocolError {
	/// The configured address pair or outer endpoint is invalid.
	InvalidAddresses,
	/// The configured keys do not establish distinct contributory identities.
	InvalidPeerKey,
	/// The sender differs from the approved outer endpoint.
	OuterEndpoint,
	/// Packet or datagram length exceeds the admitted bounds.
	PacketBounds,
	/// The inner IP header or its length is invalid.
	InvalidInnerPacket,
	/// The inner source or destination falls outside the approved address pair.
	InnerScope,
	/// A transport-key session is absent.
	NoSession,
	/// The WireGuard transport counter is outside the protocol limit.
	CounterLimit,
	/// This generation or its underlying protocol has expired.
	Expired,
	/// A monotonic observation failed or moved backwards.
	ClockUnavailable,
	/// This generation has used its bounded operation budget.
	OperationLimit,
	/// BoringTun rejected the protocol input or action.
	Rejected,
}

impl fmt::Display for ProtocolError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::InvalidAddresses => "invalid fixed-peer WireGuard addresses",
			Self::InvalidPeerKey => "invalid fixed-peer WireGuard key agreement",
			Self::OuterEndpoint => "datagram came from an unapproved outer endpoint",
			Self::PacketBounds => "packet is outside the WireGuard profile bounds",
			Self::InvalidInnerPacket => "invalid inner IP header or length",
			Self::InnerScope => "inner addresses are outside the approved peer scope",
			Self::NoSession => "the WireGuard transport-key session is unavailable",
			Self::CounterLimit => "the WireGuard transport counter reached its protocol limit",
			Self::Expired => "the WireGuard peer generation has expired",
			Self::ClockUnavailable => "the WireGuard monotonic clock is unavailable",
			Self::OperationLimit => "the WireGuard peer generation exhausted its operation budget",
			Self::Rejected => "BoringTun rejected the protocol operation",
		})
	}
}

impl std::error::Error for ProtocolError {}
