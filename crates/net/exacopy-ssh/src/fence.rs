use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, DropGuard};

pub(crate) struct FencedStream<S> {
	stream: S,
	cancelled: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl<S> FencedStream<S> {
	pub(crate) fn new(stream: S) -> (Self, DropGuard) {
		let cancellation = CancellationToken::new();
		let cancelled = Box::pin(cancellation.clone().cancelled_owned());
		(Self { stream, cancelled }, cancellation.drop_guard())
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
		Pin::new(&mut self.stream).poll_shutdown(cx)
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
		let (mut stream, owner) = FencedStream::new(stream);
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
}
