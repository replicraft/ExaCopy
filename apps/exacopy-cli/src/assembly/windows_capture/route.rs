use std::future::{Future as _, poll_fn};
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};

use exacopy_endpoint::connection_retry::{
	ConnectionAttempt, ConnectionBinding, ReconnectEvidence, RetryDecision, RetryError,
	RetrySupervisor,
};
use exacopy_endpoint::remote_source::SourceEpoch;
use exacopy_endpoint::ssh_sftp::{CredentialRequest, HostKeyFingerprint};
use exacopy_sftp::{PendingSftpSource, PendingSourceOwner};
use exacopy_ssh::{Ed25519Key, KnownHostTrust, ReadOnlySftp, connect_with_ed25519_async};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};

use super::grant::{Gate, refused};
use super::{WindowsCaptureError as Error, WindowsCaptureGrant, WindowsCaptureSource};

/// The owner of the one admitted literal route and its typed connection.
pub(super) struct SourceOwner<'a> {
	gate: &'a Gate,
	supervisor: RetrySupervisor,
}

impl<'a> SourceOwner<'a> {
	pub(super) fn new(grant: &'a WindowsCaptureGrant<'_>) -> Self {
		let gate = &grant.gate;
		Self {
			gate,
			supervisor: RetrySupervisor::new(grant.approval.supervisor, gate.expires - gate.start),
		}
	}

	pub(super) fn start(&mut self) -> Result<ConnectionAttempt, Error> {
		self.gate.route(|| ()).map_err(Error::Grant)?;
		match self
			.supervisor
			.poll(self.gate.start.elapsed())
			.map_err(Error::Retry)?
		{
			RetryDecision::Start(attempt) => Ok(attempt),
			RetryDecision::WaitUntil(_) => Err(Error::Grant(refused())),
		}
	}

	pub(super) fn admit(
		&mut self,
		route: RouteTicket,
		source: &PendingSftpSource<'_>,
		epoch: SourceEpoch,
	) -> Result<ConnectionBinding, Error> {
		let attempt = route.attempt;
		if source.attempt() != attempt || source.epoch() != epoch {
			return Err(Error::Retry(RetryError::StaleAdmission));
		}
		self.check_connecting(attempt).map_err(Error::Retry)?;
		let active = self
			.supervisor
			.admit(
				self.gate.start.elapsed(),
				attempt,
				ReconnectEvidence {
					route_checked_for: route.attempt,
					ssh_authenticated_for: route.attempt,
					source_checked_for: source.attempt(),
					source_epoch: source.epoch(),
				},
			)
			.map_err(Error::Retry)?;
		self.gate.admit(active).map_err(Error::Grant)?;
		Ok(active)
	}

	pub(super) fn check_completion(
		&mut self,
		binding: ConnectionBinding,
	) -> Result<(), RetryError> {
		self.gate
			.check(binding)
			.map_err(|_| RetryError::StaleWork)?;
		self.supervisor
			.check_completion(self.gate.start.elapsed(), binding)
	}
}

impl PendingSourceOwner for SourceOwner<'_> {
	fn check_connecting(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.gate.route(|| ()).map_err(|_| RetryError::StaleWork)?;
		self.supervisor
			.check_connecting(self.gate.start.elapsed(), attempt)
	}

	fn check_attempt(&mut self, attempt: ConnectionAttempt) -> Result<(), RetryError> {
		self.gate.route(|| ()).map_err(|_| RetryError::StaleWork)?;
		self.supervisor
			.check_attempt(self.gate.start.elapsed(), attempt)
	}
}

/// The exact stream is consumed by SSH; neither peer nor attempt can be replaced.
#[derive(Clone, Copy)]
pub(super) struct RouteTicket {
	attempt: ConnectionAttempt,
}

pub(super) struct RoutedSession {
	pub(super) ticket: RouteTicket,
	pub(super) session: ReadOnlySftp,
	closed: oneshot::Receiver<()>,
}

impl RoutedSession {
	pub(super) async fn connect<B>(
		source: &WindowsCaptureSource<'_>,
		gate: &Arc<Gate>,
		attempt: ConnectionAttempt,
		trust: KnownHostTrust,
		broker: B,
	) -> Result<Self, Error>
	where
		B: for<'a> AsyncFnOnce(CredentialRequest<'a>) -> Result<Ed25519Key, exacopy_ssh::Error>,
	{
		let deadline = Instant::from_std(gate.expires);
		let mut connect = pin!(TcpStream::connect(source.peer));
		let stream = timeout_at(
			deadline,
			poll_fn(|cx| {
				gate.route(|| connect.as_mut().poll(cx))
					.unwrap_or_else(|cause| Poll::Ready(Err(cause)))
			}),
		)
		.await
		.map_err(|_| Error::Ssh(exacopy_ssh::Error::Timeout))?
		.map_err(Error::Route)?;
		if stream.peer_addr().map_err(Error::Route)? != source.peer {
			return Err(Error::Route(io::ErrorKind::PermissionDenied.into()));
		}
		let pinned_key = HostKeyFingerprint::from_sha256(source.host_fingerprint);
		let (signal, closed) = oneshot::channel();
		let stream = AdmittedStream {
			stream,
			gate: Arc::clone(gate),
			_close: SocketClose(Some(signal)),
		};
		let offer = || gate.route(|| ()).map_err(exacopy_ssh::Error::Io);
		let session = timeout_at(
			deadline,
			connect_with_ed25519_async(
				stream,
				source.authority,
				pinned_key,
				trust,
				source.authority,
				async move |request| {
					let mut acquisition = pin!(broker(request));
					poll_fn(|cx| {
						if let Err(cause) = gate.route(|| ()) {
							return Poll::Ready(Err(exacopy_ssh::Error::Io(cause)));
						}
						acquisition.as_mut().poll(cx)
					})
					.await
				},
				offer,
			),
		)
		.await
		.map_err(|_| Error::Ssh(exacopy_ssh::Error::Timeout))?
		.map_err(Error::Ssh)?;
		let observed = session.authenticated_peer();
		if observed.authority() != source.authority || observed.fingerprint() != pinned_key {
			return Err(Error::Route(io::ErrorKind::PermissionDenied.into()));
		}
		Ok(Self {
			ticket: RouteTicket { attempt },
			session,
			closed,
		})
	}

	pub(super) async fn close(self, deadline: Instant) -> Result<(), Error> {
		self.session
			.disconnect_before(deadline)
			.await
			.map_err(Error::Ssh)?;
		timeout_at(deadline, self.closed)
			.await
			.map_err(|_| Error::Deadline)?
			.map_err(|_| Error::Route(io::ErrorKind::ConnectionAborted.into()))
	}
}

struct AdmittedStream {
	stream: TcpStream,
	gate: Arc<Gate>,
	// Fields drop in declaration order. Send only after the socket has closed.
	_close: SocketClose,
}

struct SocketClose(Option<oneshot::Sender<()>>);

impl Drop for SocketClose {
	fn drop(&mut self) {
		if let Some(closed) = self.0.take() {
			let _ = closed.send(());
		}
	}
}

impl AdmittedStream {
	fn poll_io<T>(
		&mut self,
		operation: impl FnOnce(Pin<&mut TcpStream>) -> Poll<io::Result<T>>,
	) -> Poll<io::Result<T>> {
		self.gate
			.route(|| operation(Pin::new(&mut self.stream)))
			.unwrap_or_else(|cause| Poll::Ready(Err(cause)))
	}
}

impl AsyncRead for AdmittedStream {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buffer: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		self.poll_io(|stream| stream.poll_read(cx, buffer))
	}
}

impl AsyncWrite for AdmittedStream {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bytes: &[u8],
	) -> Poll<io::Result<usize>> {
		self.poll_io(|stream| stream.poll_write(cx, bytes))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.poll_io(|stream| stream.poll_flush(cx))
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.poll_io(|stream| stream.poll_shutdown(cx))
	}
}
