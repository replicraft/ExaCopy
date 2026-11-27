use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, DropGuard};

/// Cancellation capability for one exact authenticated SSH/SFTP session.
#[derive(Clone)]
pub struct SshSessionCancellation {
	token: CancellationToken,
	shutdown: Arc<AtomicBool>,
}

impl SshSessionCancellation {
	/// Wakes pending stream I/O and refuses further reads and writes on this session.
	pub fn cancel(&self) {
		self.token.cancel();
	}

	pub(crate) fn shutdown_confirmed(&self) -> bool {
		self.shutdown.load(Ordering::Acquire)
	}
}

pub(crate) struct FencedStream<S> {
	stream: S,
	cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
	shutdown: Arc<AtomicBool>,
}

impl<S> FencedStream<S> {
	pub(crate) fn new(stream: S) -> (Self, DropGuard, SshSessionCancellation) {
		let cancellation = CancellationToken::new();
		let cancelled = Box::pin(cancellation.clone().cancelled_owned());
		let shutdown = Arc::new(AtomicBool::new(false));
		(
			Self {
				stream,
				cancelled,
				shutdown: Arc::clone(&shutdown),
			},
			cancellation.clone().drop_guard(),
			SshSessionCancellation {
				token: cancellation,
				shutdown,
			},
		)
	}

	fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
		if self.cancelled.as_mut().poll(cx).is_ready() {
			return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
		}
		Ok(())
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for FencedStream<S> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		output: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		self.check(cx)?;
		Pin::new(&mut self.stream).poll_read(cx, output)
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FencedStream<S> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bytes: &[u8],
	) -> Poll<io::Result<usize>> {
		self.check(cx)?;
		Pin::new(&mut self.stream).poll_write(cx, bytes)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.check(cx)?;
		Pin::new(&mut self.stream).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		std::task::ready!(Pin::new(&mut self.stream).poll_shutdown(cx))?;
		self.shutdown.store(true, Ordering::Release);
		Poll::Ready(Ok(()))
	}
}

#[cfg(test)]
mod tests {
	use std::io::ErrorKind;

	use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

	use super::FencedStream;

	#[tokio::test]
	async fn dropping_the_owner_wakes_an_idle_read_and_fences_future_writes() {
		let (stream, peer) = duplex(64);
		let (mut stream, owner, _) = FencedStream::new(stream);
		let (read, ()) = tokio::join!(stream.read_u8(), async {
			tokio::task::yield_now().await;
			drop(owner);
		});
		assert_eq!(read.unwrap_err().kind(), ErrorKind::ConnectionAborted);
		assert_eq!(
			stream.write_u8(0).await.unwrap_err().kind(),
			ErrorKind::ConnectionAborted
		);
		drop(peer);
	}
	#[tokio::test]
	async fn explicit_handle_wakes_pending_io_without_cancelling_another_session() {
		let (read_stream, _read_peer) = duplex(1);
		let (mut read, _read_owner, read_cancel) = FencedStream::new(read_stream);
		let (write_stream, _write_peer) = duplex(1);
		let (mut write, _write_owner, write_cancel) = FencedStream::new(write_stream);
		let (control_stream, mut control_peer) = duplex(1);
		let (mut control, _control_owner, _) = FencedStream::new(control_stream);

		write.write_u8(1).await.unwrap();
		let (read_result, write_result, ()) =
			tokio::join!(read.read_u8(), write.write_u8(2), async {
				tokio::task::yield_now().await;
				read_cancel.clone().cancel();
				write_cancel.cancel();
			},);
		assert_eq!(
			read_result.unwrap_err().kind(),
			ErrorKind::ConnectionAborted
		);
		assert_eq!(
			write_result.unwrap_err().kind(),
			ErrorKind::ConnectionAborted
		);
		assert_eq!(
			write.write_u8(3).await.unwrap_err().kind(),
			ErrorKind::ConnectionAborted
		);
		control_peer.write_u8(7).await.unwrap();
		assert_eq!(control.read_u8().await.unwrap(), 7);
	}
}
