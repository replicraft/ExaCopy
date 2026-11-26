use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use exacopy_journal::remote_download::RemoteScopeDigest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use super::super::RemoteGrant;
use super::super::route_lifetime::RouteActivity;

/// Adds the exact grant and route gate to the socket consumed by pinned SSH.
pub(super) struct GrantedStream {
	stream: TcpStream,
	grant: Arc<RemoteGrant>,
	scope: RemoteScopeDigest,
	route: Arc<RouteActivity>,
	// Fields drop in declaration order. The held socket closes before this signal.
	_closed: AfterSocketDrop,
}

struct AfterSocketDrop {
	route: Arc<RouteActivity>,
	closed: Option<oneshot::Sender<()>>,
}

impl Drop for AfterSocketDrop {
	fn drop(&mut self) {
		self.route.stop();
		if let Some(closed) = self.closed.take() {
			let _ = closed.send(());
		}
	}
}

impl GrantedStream {
	pub(super) fn new(
		stream: TcpStream,
		grant: Arc<RemoteGrant>,
		scope: RemoteScopeDigest,
		route: Arc<RouteActivity>,
	) -> (Self, oneshot::Receiver<()>) {
		let (closed, observed) = oneshot::channel();
		(
			Self {
				stream,
				grant,
				scope,
				route: Arc::clone(&route),
				_closed: AfterSocketDrop {
					route,
					closed: Some(closed),
				},
			},
			observed,
		)
	}

	fn io<T>(
		&mut self,
		operation: impl FnOnce(Pin<&mut TcpStream>) -> Poll<io::Result<T>>,
	) -> Poll<io::Result<T>> {
		self.route.with_grant(&self.grant, self.scope, |current| {
			if current {
				operation(Pin::new(&mut self.stream))
			} else {
				refused()
			}
		})
	}
}

pub(super) fn refused<T>() -> Poll<io::Result<T>> {
	Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()))
}

impl AsyncRead for GrantedStream {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		self.io(|stream| stream.poll_read(cx, buf))
	}
}

impl AsyncWrite for GrantedStream {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bytes: &[u8],
	) -> Poll<io::Result<usize>> {
		self.io(|stream| stream.poll_write(cx, bytes))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.io(|stream| stream.poll_flush(cx))
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.io(|stream| stream.poll_shutdown(cx))
	}
}

#[cfg(test)]
mod tests {
	use std::time::{Duration, Instant};

	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	use super::super::super::route_lifetime::RouteLease;
	use super::*;

	#[tokio::test]
	async fn retirement_fences_the_exact_direct_socket_and_acknowledges_its_close() {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let target = listener.local_addr().unwrap();
		let (client, server) = tokio::join!(TcpStream::connect(target), listener.accept());
		let (mut server, _) = server.unwrap();
		let scope = RemoteScopeDigest::from_bytes([1; 32]);
		let grant = Arc::new(
			RemoteGrant::new(scope, [2; 32], Instant::now() + Duration::from_secs(60)).unwrap(),
		);
		let lease = RouteLease::new();
		let (mut stream, mut closed) =
			GrantedStream::new(client.unwrap(), Arc::clone(&grant), scope, lease.activity());
		stream.write_u8(1).await.unwrap();
		assert_eq!(server.read_u8().await.unwrap(), 1);
		drop(lease);
		assert_eq!(
			stream.write_u8(2).await.unwrap_err().kind(),
			io::ErrorKind::ConnectionAborted
		);
		assert_eq!(
			stream.flush().await.unwrap_err().kind(),
			io::ErrorKind::ConnectionAborted
		);
		assert_eq!(
			stream.read_u8().await.unwrap_err().kind(),
			io::ErrorKind::ConnectionAborted
		);
		assert_eq!(closed.try_recv(), Err(oneshot::error::TryRecvError::Empty));
		drop(stream);
		tokio::time::timeout(Duration::from_secs(1), closed)
			.await
			.unwrap()
			.unwrap();
		let mut next = [0];
		assert_eq!(server.read(&mut next).await.unwrap(), 0);
		assert!(grant.check_source(scope).is_ok());
	}

	#[tokio::test]
	async fn a_socket_poll_checks_the_deadline_even_without_a_watchdog_poll() {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let target = listener.local_addr().unwrap();
		let (client, server) = tokio::join!(TcpStream::connect(target), listener.accept());
		let (mut server, _) = server.unwrap();
		let scope = RemoteScopeDigest::from_bytes([1; 32]);
		let deadline = Instant::now() + Duration::from_secs(1);
		let grant = Arc::new(RemoteGrant::new(scope, [2; 32], deadline).unwrap());
		let lease = RouteLease::new();
		let (mut stream, _) = GrantedStream::new(client.unwrap(), grant, scope, lease.activity());
		tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
		assert_eq!(
			stream.write_u8(3).await.unwrap_err().kind(),
			io::ErrorKind::ConnectionAborted
		);
		drop(stream);
		let mut next = [0];
		assert_eq!(server.read(&mut next).await.unwrap(), 0);
	}
}
