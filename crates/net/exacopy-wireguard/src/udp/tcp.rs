//! Composition of the fixed UDP peer and one admitted inner stream.

use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use exacopy_endpoint::wireguard::{EmbeddedDialCommand, RouteObservation};

use crate::protocol::PeerBinding;
use crate::stack::{
	InnerMtu, InnerTcp, InnerTcpStream, PumpError, RouteRevocation, TcpFlow, TcpFlowStatus, TcpPump,
};

use super::{RouteOwner, UdpError, UdpPeer};

mod error;
mod packet_io;
#[cfg(test)]
mod tests;

pub use error::UdpTcpError;

use packet_io::UdpPacketIo;

/// Extends route ownership with the exact generation's stream revocation signal.
///
/// The owner keeps one signal per generation and invalidates that generation
/// permanently under the same authority used for outer submission.
pub trait TcpRouteOwner: RouteOwner {
	/// Clones the current generation's signal or refuses stale authority.
	fn stream_revocation(&self, binding: RouteObservation) -> Option<RouteRevocation>;
}

/// Application-supplied parameters for the approved inner TCP connection.
pub struct TcpDialSettings {
	/// A fresh client port in the selected inner address family.
	pub local_port: NonZeroU16,
	/// Effective outer path MTU after deducting any additional enclosure bytes.
	pub outer_path_mtu: u16,
	/// Caller-supplied unpredictable entropy for the TCP sequence space.
	pub random_seed: u64,
}

/// An admitted stream, driver and their locked-in route identity.
///
/// The caller transfers this carrier as a whole to the stream consumer.
pub struct UdpTcpAdmission<R> {
	route: UdpTcpRoute<R>,
	stream: InnerTcpStream,
	driver: UdpTcpDriver<R>,
}

/// Current route observation of the exact enclosed TCP stream.
pub struct UdpTcpRoute<R> {
	peer: UdpTcpPeer,
	status: TcpFlowStatus,
	owner: Arc<R>,
	route: RouteObservation,
}

impl<R: RouteOwner> UdpTcpRoute<R> {
	/// Observes the peer of the original established flow while it is current.
	///
	/// The driver and stream fence invalidates this observation on cancellation,
	/// route revocation and driver exit. This observation grants no UDP authority.
	#[must_use]
	pub fn current(&self) -> Option<UdpTcpPeer> {
		self.owner.with_observation(|current| {
			(current == self.route && self.status.is_live()).then_some(self.peer)
		})
	}
}

/// A point-in-time observation of an admitted embedded TCP peer.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UdpTcpPeer {
	binding: PeerBinding,
	remote_public_key: [u8; 32],
	inner: SocketAddr,
}

impl UdpTcpPeer {
	/// The owning actor, profile revision and generation. One actor generation
	/// admits only one stream through the consuming dial operation.
	#[must_use]
	pub const fn binding(self) -> PeerBinding {
		self.binding
	}

	/// The actual fixed public key installed in the WireGuard provider.
	#[must_use]
	pub const fn remote_public_key(self) -> [u8; 32] {
		self.remote_public_key
	}

	/// The inner TCP peer selected by the consumed dial command.
	#[must_use]
	pub const fn inner(self) -> SocketAddr {
		self.inner
	}
}

impl<R> UdpTcpAdmission<R> {
	/// Makes the stream's write shutdown wait for the exact TCP driver to close.
	///
	/// Opt in only when the stream owner can keep the driver running and
	/// bound the wait with its original route authority. A revoked or failed
	/// driver cannot confirm shutdown.
	#[must_use]
	pub fn with_confirmed_shutdown(mut self) -> Self {
		self.driver.pump.confirm_shutdown(&mut self.stream);
		self
	}

	/// Consumes the admission into a scoped stream operation.
	///
	/// Run the supplied driver concurrently while using the stream. Observe the
	/// borrowed route only for this stream, through its terminal protocol checks.
	/// The trusted application owns that composition and joins the driver.
	///
	/// ```compile_fail
	/// use exacopy_wireguard::udp::{UdpTcpAdmission, UdpTcpRoute};
	///
	/// async fn separate_route<R>(admission: UdpTcpAdmission<R>) -> &'static UdpTcpRoute<R> {
	///     admission.with_stream(async |_, _, route| route).await
	/// }
	/// ```
	pub async fn with_stream<T>(
		self,
		consume: impl AsyncFnOnce(InnerTcpStream, UdpTcpDriver<R>, &UdpTcpRoute<R>) -> T,
	) -> T {
		consume(self.stream, self.driver, &self.route).await
	}
}

/// The uniquely owned UDP and TCP driver for one admitted flow.
pub struct UdpTcpDriver<R> {
	pump: TcpPump,
	packets: UdpPacketIo<Arc<R>>,
}

impl<R: TcpRouteOwner + Send + Sync> UdpPeer<R> {
	/// Consumes one peer and one approved inner dial into a stream and driver.
	///
	/// The RouteOwner binds and shares one revocation signal for this generation.
	/// The caller supervises the driver alongside the stream user.
	///
	/// # Errors
	/// Refuses stale authority, missing WireGuard session, an unapproved dial,
	/// an unsuitable MTU or a mismatched revocation signal.
	pub fn into_tcp(
		mut self,
		command: EmbeddedDialCommand,
		settings: TcpDialSettings,
	) -> Result<UdpTcpAdmission<R>, UdpTcpError> {
		let target = self.admit_inner_dial(command)?;
		let revocation = self
			.owner
			.stream_revocation(self.binding)
			.ok_or(UdpError::RouteChanged)?;
		let protocol = &self.active.as_ref().ok_or(UdpError::Retired)?.protocol;
		let binding = protocol.binding();
		let remote_public_key = protocol.remote_public_key();
		let mtu = InnerMtu::from_outer(protocol.outer_endpoint(), settings.outer_path_mtu)?;
		let inner = target.address();
		let flow = TcpFlow {
			binding,
			local: SocketAddr::new(protocol.inner_local(), settings.local_port.get()),
			remote: inner,
			mtu,
		};
		let (stream, mut pump) =
			InnerTcp::connect(flow, settings.random_seed)?.into_async(revocation)?;
		let owner = Arc::new(self.owner);
		let route = UdpTcpRoute {
			owner: Arc::clone(&owner),
			route: self.binding,
			peer: UdpTcpPeer {
				binding,
				remote_public_key,
				inner,
			},
			status: pump.track_flow(),
		};
		let packets = UdpPacketIo::new(
			UdpPeer {
				owner,
				binding: self.binding,
				active: self.active,
			},
			binding,
		)?;
		Ok(UdpTcpAdmission {
			route,
			stream,
			driver: UdpTcpDriver { pump, packets },
		})
	}
}

impl<R: RouteOwner + Send + Sync> UdpTcpDriver<R> {
	/// Runs this flow's bounded driver until confirmed close or failure.
	///
	/// # Errors
	/// Reports a route or protocol failure, local cancellation or a deadline.
	///
	/// # Panics
	/// Requires a Tokio runtime with its time and I/O drivers enabled.
	pub async fn run(self) -> Result<(), PumpError<UdpTcpError>> {
		self.pump.run(self.packets).await
	}
}

impl<R: RouteOwner> RouteOwner for Arc<R> {
	fn with_observation<T>(&self, observe: impl FnOnce(RouteObservation) -> T) -> T {
		(**self).with_observation(observe)
	}

	fn claim_generation(&self, binding: RouteObservation) -> bool {
		(**self).claim_generation(binding)
	}
}
