use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use exacopy_endpoint::UnixComponent;
use exacopy_ssh::{Error, Password, connect};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::peer::{CONTENT, Calls, NAME, SECRET, authority, fixture_trust, peer};

const FOREGROUND_WAIT: Duration = Duration::from_secs(5);
const TERMINAL_WAIT: Duration = Duration::from_secs(4);

#[test]
#[ignore = "demonstrates actual 21-second quiet read-back on another thread"]
fn authenticated_keepalives_preserve_the_same_held_source_during_quiet_readback() {
	quiet_capture(Duration::from_secs(21), true);
}

#[test]
#[ignore = "waits for the bounded live keepalive refusal"]
fn a_nonresponsive_peer_cannot_complete_terminal_source_proof() {
	quiet_capture(Duration::from_secs(18), false);
}

fn quiet_capture(quiet: Duration, responsive: bool) {
	thread::scope(|scope| {
		let (ready, started) = mpsc::channel();
		let (resume, verify) = oneshot::channel();
		let worker = scope.spawn(move || {
			tokio::runtime::Builder::new_current_thread()
				.enable_time()
				.build()
				.unwrap()
				.block_on(async {
					let (transport, pin, calls) = peer(true, false);
					let muted = Arc::new(AtomicBool::new(false));
					let target = authority("transfer");
					let mut session = connect(
						ResponseGate {
							transport,
							muted: Arc::clone(&muted),
						},
						&target,
						pin,
						fixture_trust(&target, ""),
						&target,
						|_| Password::new(SECRET.to_owned()),
					)
					.await
					.unwrap();
					let path = [UnixComponent::new(NAME).unwrap()];
					let mut source = session.open_positioned(&path).await.unwrap();
					let observation = source.observation();
					assert_eq!(observation.length, CONTENT.len() as u64);
					let mut window = source.begin_window(0, observation.length).await.unwrap();
					let mut bytes = [0; CONTENT.len()];
					let mut used = 0;
					while used < bytes.len() {
						let count = window.read_next(&mut bytes[used..]).await.unwrap();
						assert!(count > 0);
						used += count;
					}
					assert_eq!(&bytes, CONTENT);
					window.finish().await.unwrap();
					let before = sample(&calls);
					assert_eq!(calls.open.load(Ordering::Relaxed), 1);
					assert_eq!(before.closes, 0);
					if !responsive {
						muted.store(true, Ordering::Release);
					}
					ready.send(()).unwrap();
					timeout(Duration::from_secs(30), verify)
						.await
						.unwrap()
						.unwrap();
					assert_eq!(sample(&calls), before);
					let terminal = timeout(TERMINAL_WAIT, source.finish()).await.unwrap();
					if responsive {
						assert_eq!(terminal.unwrap(), observation);
						assert_eq!(calls.open.load(Ordering::Relaxed), 1);
						assert_eq!(
							sample(&calls),
							FileRequests {
								reads: before.reads + 1,
								held_stats: before.held_stats + 1,
								named_stats: before.named_stats + 1,
								closes: before.closes + 1,
							}
						);
					} else {
						assert!(
							matches!(terminal, Err(Error::Ssh(russh::Error::KeepaliveTimeout))),
							"quiet peer should fail by missed keepalive bound: {terminal:?}"
						);
						assert_eq!(sample(&calls), before);
						assert!(matches!(session.stat(&path).await, Err(Error::Closed)));
					}
				});
		});
		started.recv_timeout(FOREGROUND_WAIT).unwrap();
		// The foreground can block during local read-back while the SSH
		// worker continues driving authenticated transport traffic.
		thread::sleep(quiet);
		resume.send(()).unwrap();
		worker.join().unwrap();
	});
}

#[derive(Debug, Eq, PartialEq)]
struct FileRequests {
	reads: usize,
	held_stats: usize,
	named_stats: usize,
	closes: usize,
}

fn sample(calls: &Calls) -> FileRequests {
	FileRequests {
		reads: calls.read.load(Ordering::Relaxed),
		held_stats: calls.held_stat.load(Ordering::Relaxed),
		named_stats: calls.named_stat.load(Ordering::Relaxed),
		closes: calls.close.load(Ordering::Relaxed),
	}
}

struct ResponseGate {
	transport: DuplexStream,
	muted: Arc<AtomicBool>,
}

impl AsyncRead for ResponseGate {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buffer: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		if self.muted.load(Ordering::Acquire) {
			return Poll::Pending;
		}
		Pin::new(&mut self.transport).poll_read(cx, buffer)
	}
}

impl AsyncWrite for ResponseGate {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bytes: &[u8],
	) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.transport).poll_write(cx, bytes)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.transport).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.transport).poll_shutdown(cx)
	}
}
