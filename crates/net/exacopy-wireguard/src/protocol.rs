//! One fixed WireGuard peer with caller-owned packet buffers and no socket API.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU64, NonZeroU128};

use boringtun::noise::{TransportKeyResult, Tunn, TunnResult};
pub use boringtun::x25519::{PublicKey, StaticSecret};

mod clock;
mod lifecycle;
mod packet;
#[cfg(test)]
mod tests;

use clock::GenerationClock;
use lifecycle::KeyLifetime;
use packet::{addresses, admitted_counter, handshake_ephemeral, is_literal_unicast};

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
// A public X25519 probe uses 2^254 after clamping. A power-of-two scalar
// kills the cofactor component while retaining every nontrivial odd-order component.
const EPHEMERAL_PROBE_SCALAR: [u8; 32] = [0; 32];
const MAX_INCOMING_HANDSHAKES: u16 = 256;

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
	/// Whether the current outbound transport pair is admitted and confirmed.
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
/// An authenticated selected key can renew the existing time and work bounds.
/// Each retained key is independently fenced under the same monotonic clock
/// as BoringTun. Rekey retains the route binding and surviving replay windows.
/// Ownership of this value alone conveys no I/O or runtime qualification.
pub struct ProtocolPeer {
	binding: PeerBinding,
	#[cfg(all(feature = "experimental-udp", feature = "experimental-tcp"))]
	remote_public_key: [u8; 32],
	endpoints: PeerAddresses,
	tunnel: Tunn,
	clock: GenerationClock,
	keys: KeyLifetime,
	operations_remaining: u32,
	handshakes_remaining: u16,
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
		#[cfg(all(feature = "experimental-udp", feature = "experimental-tcp"))]
		let remote_public_key = remote_public.to_bytes();
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
			#[cfg(all(feature = "experimental-udp", feature = "experimental-tcp"))]
			remote_public_key,
			endpoints,
			tunnel,
			clock,
			keys: KeyLifetime::default(),
			operations_remaining: MAX_GENERATION_OPERATIONS,
			handshakes_remaining: MAX_INCOMING_HANDSHAKES,
		})
	}

	#[cfg(feature = "experimental-udp")]
	pub(super) const fn binding(&self) -> PeerBinding {
		self.binding
	}

	#[cfg(all(feature = "experimental-udp", feature = "experimental-tcp"))]
	pub(super) const fn remote_public_key(&self) -> [u8; 32] {
		self.remote_public_key
	}

	#[cfg(all(feature = "experimental-udp", feature = "experimental-tcp"))]
	pub(super) const fn inner_local(&self) -> IpAddr {
		self.endpoints.local
	}

	#[cfg(feature = "experimental-udp")]
	pub(super) const fn outer_endpoint(&self) -> SocketAddr {
		self.endpoints.outer
	}

	#[cfg(feature = "experimental-udp")]
	pub(super) const fn inner_remote(&self) -> IpAddr {
		self.endpoints.remote
	}

	#[cfg(feature = "experimental-udp")]
	pub(super) fn check_generation(&mut self) -> Result<(), ProtocolError> {
		self.require_available()?;
		self.clock.advance()
	}

	#[cfg(feature = "experimental-udp")]
	pub(super) fn check_output(&mut self, packet: &PacketOutput<'_>) -> Result<(), ProtocolError> {
		self.check_output_key(packet)
	}

	#[cfg(feature = "experimental-udp")]
	pub(super) fn has_session(&self) -> bool {
		self.selected_is_admitted()
	}

	#[cfg(all(test, feature = "experimental-udp"))]
	pub(super) fn expire_for_test(&mut self) {
		self.clock.expire_for_test();
	}

	#[cfg(all(test, feature = "experimental-tcp"))]
	pub(crate) fn advance_rekey_clock_for_test(&mut self, delta: std::time::Duration) {
		self.clock.advance_for_test(delta);
	}

	#[cfg(all(test, feature = "experimental-tcp"))]
	pub(crate) fn selected_key_for_test(&self) -> boringtun::noise::TransportKeyId {
		self.tunnel.current_transport_key().unwrap().id
	}

	/// Returns the current key-slot observation for this actor and generation.
	#[must_use]
	pub fn observation(&self) -> SessionObservation {
		SessionObservation {
			binding: self.binding,
			has_session: self.require_available().is_ok() && self.selected_is_admitted(),
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
		self.prepare_tunnel()?;
		let result = self.tunnel.format_handshake_initiation(output, false);
		self.translate(TransportKeyResult {
			result,
			key_use: None,
		})
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
		let now = self.prepare_tunnel()?;
		let result = self.tick_tunnel(output, now);
		self.translate(result)
	}

	/// Processes one bounded datagram from the one approved outer endpoint.
	/// A returned control packet does not establish a fresh peer observation.
	/// # Errors
	/// Refuses foreign senders, invalid datagrams, failed authentication and
	/// decrypted packets outside the approved inner address pair. A fixed
	/// budget caps unauthenticated ephemeral checks before library processing.
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
		let ephemeral = handshake_ephemeral(datagram)?;
		if ephemeral.is_some() && self.handshakes_remaining == 0 {
			self.require_active()?;
			return Err(ProtocolError::HandshakeLimit);
		}

		self.reserve_operation()?;
		if let Some(public_bytes) = ephemeral {
			self.handshakes_remaining -= 1;
			let public_key = PublicKey::from(*public_bytes);
			// This public probe is independent of the tunnel's private key.
			let probe = StaticSecret::from(EPHEMERAL_PROBE_SCALAR);
			if !probe.diffie_hellman(&public_key).was_contributory() {
				return Err(ProtocolError::NonContributoryEphemeral);
			}
			self.clock.advance()?;
		}
		let started = self.prepare_tunnel()?;
		let result =
			self.tunnel
				.decapsulate_with_transport_key(Some(sender.ip()), datagram, output);
		if ephemeral.is_some() {
			self.register_key_installation(started)?;
		}
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
		if !self.selected_is_admitted() {
			return Err(ProtocolError::NoSession);
		}
		self.check_inner(packet, self.endpoints.local, self.endpoints.remote)?;
		self.reserve_operation()?;
		self.prepare_tunnel()?;
		if !self.selected_is_admitted() {
			return Err(ProtocolError::NoSession);
		}
		let result = self.tunnel.encapsulate_with_transport_key(packet, output);
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
		tagged: TransportKeyResult<'buffer>,
	) -> Result<PacketOutput<'buffer>, ProtocolError> {
		if self.tunnel.is_expired() {
			return Err(ProtocolError::Expired);
		}
		self.clock.advance()?;
		if let TunnResult::WriteToTunnelV4(ref bytes, _)
		| TunnResult::WriteToTunnelV6(ref bytes, _) = tagged.result
		{
			self.check_inner(bytes, self.endpoints.remote, self.endpoints.local)?;
		}
		self.admit_result(&tagged.result, tagged.key_use)?;
		match tagged.result {
			TunnResult::Done => Ok(PacketOutput::None),
			TunnResult::Err(_) => Err(ProtocolError::Rejected),
			TunnResult::WriteToNetwork(bytes) => Ok(PacketOutput::Outer {
				destination: self.endpoints.outer,
				bytes,
			}),
			TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
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
	/// The received handshake ephemeral is not contributory under X25519.
	NonContributoryEphemeral,
	/// This generation exhausted its incoming handshake allowance.
	HandshakeLimit,
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
			Self::NonContributoryEphemeral => "invalid WireGuard handshake ephemeral key",
			Self::HandshakeLimit => {
				"the WireGuard peer generation exhausted its handshake allowance"
			}
			Self::Expired => "the WireGuard peer generation has expired",
			Self::ClockUnavailable => "the WireGuard monotonic clock is unavailable",
			Self::OperationLimit => "the WireGuard peer generation exhausted its operation budget",
			Self::Rejected => "BoringTun rejected the protocol operation",
		})
	}
}

impl std::error::Error for ProtocolError {}
