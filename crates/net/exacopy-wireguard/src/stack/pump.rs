use std::error::Error;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::protocol::{INNER_MTU, PeerBinding};

use super::{InnerTcp, PacketDisposition, TcpError, TcpState};

mod drive;
#[cfg(test)]
mod tests;

const PIPE_BYTES: usize = 16 * 1024;

/// Packet operations owned by a single authenticated route generation.
///
/// The owner performs the final lease checks at send and receive delivery and
/// wakes idle waiters promptly on revocation. Outer timers and keys belong to
/// the owner. Any packet buffer is borrowed only for the current call.
pub trait PacketIo: Send {
	/// Typed failure of the underlying authenticated route.
	type Error: Error + Send + Sync + 'static;

	/// Rechecks the flow against the currently bound route.
	///
	/// # Errors
	/// Refuses an expired, stale, revoked, or changed route.
	fn check(&mut self, binding: PeerBinding) -> Result<(), Self::Error>;

	/// Offers one packet under the exact supplied route binding.
	///
	/// The owner serializes its lease check with the actual outer submission.
	/// Acceptance asserts that the selected egress accepted the packet.
	/// Readiness, encryption and internal queuing alone do not qualify.
	///
	/// # Errors
	/// Returns a route or packet submission failure.
	fn send(
		&mut self,
		binding: PeerBinding,
		packet: &[u8],
	) -> Result<PacketDisposition, Self::Error>;

	/// Waits for one event without borrowing an application queue.
	///
	/// The future must be cancellation-safe. Only report writable readiness
	/// when requested, and only deliver verified packets when receive is
	/// requested. Route loss wakes the future regardless of interest.
	///
	/// # Errors
	/// Returns a route or packet reception failure.
	fn wait(
		&mut self,
		interest: PacketInterest,
		packet: &mut [u8; INNER_MTU],
	) -> impl Future<Output = Result<PacketEvent, Self::Error>> + Send;
}

/// Flow events the pump is currently able to use.
#[derive(Clone, Copy)]
pub struct PacketInterest {
	/// A packet may be delivered into the bounded receive slot.
	pub receive: bool,
	/// An earlier packet offer encountered backpressure.
	pub writable: bool,
}

/// A single completed event for the registered packet interest.
pub enum PacketEvent {
	/// An authenticated packet was delivered into the supplied buffer.
	Received(usize),
	/// One pending send may be attempted again.
	Writable,
}

/// Failure of the caller-owned stream driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum PumpError<E> {
	/// The pipe consumer or driver was cancelled.
	Cancelled,
	/// The route owner permanently revoked this flow generation.
	RouteRevoked,
	/// The flow's connect, shutdown or final cleanup deadline elapsed.
	Deadline,
	/// The actor supplied an unexpected readiness event.
	UnexpectedEvent,
	/// An authenticated route operation failed.
	Route(E),
	/// An inner TCP state or packet operation failed.
	Tcp(TcpError),
	/// The local asynchronous pipe could not complete.
	Pipe(io::Error),
}

impl<E: fmt::Display> fmt::Display for PumpError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Cancelled => formatter.write_str("inner TCP pump was cancelled"),
			Self::RouteRevoked => formatter.write_str("inner TCP route generation was revoked"),
			Self::Deadline => formatter.write_str("inner TCP pump exceeded its deadline"),
			Self::UnexpectedEvent => formatter.write_str("unexpected inner packet readiness event"),
			Self::Route(error) => write!(formatter, "inner TCP route failed ({error})"),
			Self::Tcp(error) => error.fmt(formatter),
			Self::Pipe(error) => error.fmt(formatter),
		}
	}
}

impl<E: Error + 'static> Error for PumpError<E> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Route(error) => Some(error),
			Self::Tcp(error) => Some(error),
			Self::Pipe(error) => Some(error),
			_ => None,
		}
	}
}

/// One permanently revocable signal for an admitted route generation.
///
/// Create this once for the exact binding and share its clones with flows and
/// the owner. This signal cannot grant egress authority. The route owner
/// still retires its lease and serializes lease validation and actual
/// submission. The supervisor rechecks the binding before using a completion
/// that raced revocation.
#[derive(Clone)]
pub struct RouteRevocation {
	binding: PeerBinding,
	token: CancellationToken,
}

impl RouteRevocation {
	/// Creates the signal for a newly admitted generation.
	#[must_use]
	pub fn new(binding: PeerBinding) -> Self {
		Self {
			binding,
			token: CancellationToken::new(),
		}
	}

	/// Permanently revokes this generation through all clones.
	pub fn revoke(&self) {
		self.token.cancel();
	}
}

/// A bounded async stream suitable for a caller-stream SSH adapter.
///
/// Write and flush describe acceptance into the local pipe. The first
/// admitted shutdown starts the driver's bounded graceful close. Route
/// revocation and an incomplete driver teardown both fence future polls.
pub struct InnerTcpStream {
	// Notify the driver before dropping the application pipe.
	_guard: DropGuard,
	pipe: DuplexStream,
	cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
	revoked: Pin<Box<dyn Future<Output = ()> + Send>>,
	shutdown: watch::Sender<Option<Instant>>,
}

/// The uniquely owned driver of one asynchronous inner TCP stream.
pub struct TcpPump {
	// Field drop order fences application polls before pipe teardown wakes them.
	guard: Option<DropGuard>,
	pipe: DuplexStream,
	tcp: InnerTcp,
	signals: Signals,
}

struct Signals {
	cancelled: CancellationToken,
	route: RouteRevocation,
	shutdown: watch::Receiver<Option<Instant>>,
	#[cfg(feature = "experimental-udp")]
	open: Option<watch::Sender<bool>>,
}

#[cfg(feature = "experimental-udp")]
pub(crate) struct TcpFlowStatus {
	open: watch::Receiver<bool>,
	cancelled: CancellationToken,
	route: RouteRevocation,
}

#[cfg(feature = "experimental-udp")]
impl TcpFlowStatus {
	pub(crate) fn is_live(&self) -> bool {
		*self.open.borrow()
			&& self.open.has_changed().is_ok()
			&& !self.cancelled.is_cancelled()
			&& !self.route.token.is_cancelled()
	}
}

impl InnerTcp {
	/// Creates a stream and its driver without running or spawning either side.
	///
	/// The supervisor must poll the driver and the stream user concurrently.
	///
	/// # Errors
	/// Refuses a mismatched or revoked generation, a closing or closed flow,
	/// or a flow whose raw elapsed clock has already advanced past zero.
	pub fn into_async(self, route: RouteRevocation) -> Result<(InnerTcpStream, TcpPump), TcpError> {
		if route.binding != self.binding() {
			return Err(TcpError::RouteMismatch);
		}
		if route.token.is_cancelled()
			|| !matches!(self.state(), TcpState::Opening | TcpState::Writable)
		{
			return Err(TcpError::Closed);
		}
		if self.live.as_ref().is_some_and(|live| !live.clock.is_zero()) {
			return Err(TcpError::Clock);
		}
		let (application, driver) = duplex(PIPE_BYTES);
		let (request, shutdown) = watch::channel(None);
		let cancelled = CancellationToken::new();
		let stream = InnerTcpStream {
			_guard: cancelled.clone().drop_guard(),
			pipe: application,
			cancelled: Box::pin(cancelled.clone().cancelled_owned()),
			revoked: Box::pin(route.token.clone().cancelled_owned()),
			shutdown: request,
		};
		let pump = TcpPump {
			guard: Some(cancelled.clone().drop_guard()),
			pipe: driver,
			tcp: self,
			signals: Signals {
				cancelled,
				route,
				shutdown,
				#[cfg(feature = "experimental-udp")]
				open: None,
			},
		};
		Ok((stream, pump))
	}
}

impl TcpPump {
	#[cfg(feature = "experimental-udp")]
	pub(crate) fn track_flow(&mut self) -> TcpFlowStatus {
		let (open, receive) = watch::channel(false);
		self.signals.open = Some(open);
		TcpFlowStatus {
			open: receive,
			cancelled: self.signals.cancelled.clone(),
			route: self.signals.route.clone(),
		}
	}

	/// Runs the driver under the caller's supervisor and Tokio time driver.
	///
	/// The driver allows 30 seconds to connect and 20 seconds from the first
	/// local shutdown request for drain and TCP close. Reaching TCP TIME-WAIT
	/// starts a separate 20-second cleanup limit. Independent owner deadlines
	/// and generation revocation may end any phase earlier.
	///
	/// Dropping this future fences the stream before tearing down the pipe.
	///
	/// # Errors
	/// Returns route loss, unexpected readiness, timeout or local pipe failure.
	///
	/// # Panics
	/// Requires Tokio's time driver when polled.
	pub async fn run<I: PacketIo>(mut self, mut io: I) -> Result<(), PumpError<I::Error>> {
		let result = drive::run(&mut self.tcp, &mut self.pipe, &mut self.signals, &mut io).await;
		if result.is_ok()
			&& let Some(guard) = self.guard.take()
		{
			guard.disarm();
		}
		result
	}
}

impl InnerTcpStream {
	fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
		if self.revoked.as_mut().poll(cx).is_ready() || self.cancelled.as_mut().poll(cx).is_ready()
		{
			return Err(io::ErrorKind::ConnectionAborted.into());
		}
		Ok(())
	}
}

impl AsyncRead for InnerTcpStream {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buffer: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		self.check(cx)?;
		Pin::new(&mut self.pipe).poll_read(cx, buffer)
	}
}

impl AsyncWrite for InnerTcpStream {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bytes: &[u8],
	) -> Poll<io::Result<usize>> {
		self.check(cx)?;
		Pin::new(&mut self.pipe).poll_write(cx, bytes)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.check(cx)?;
		Pin::new(&mut self.pipe).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.check(cx)?;
		self.shutdown.send_if_modified(|requested| {
			if requested.is_some() {
				return false;
			}
			*requested = Some(Instant::now());
			true
		});
		Pin::new(&mut self.pipe).poll_shutdown(cx)
	}
}
