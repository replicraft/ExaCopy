use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio::time::timeout;

use crate::stack::TcpFlow;
use crate::stack::tests::{ipv4_flow, ipv6_flow, pair};

use super::*;

struct Packet {
	bytes: [u8; INNER_MTU],
	len: usize,
}

struct TestPackets {
	sender: mpsc::Sender<Packet>,
	receiver: mpsc::Receiver<Packet>,
	binding: PeerBinding,
	revoked: CancellationToken,
	waited: Arc<Notify>,
	writable_events: Arc<AtomicUsize>,
	block_once: bool,
	blocked: bool,
}

impl PacketIo for TestPackets {
	type Error = io::Error;

	fn check(&mut self, binding: PeerBinding) -> Result<(), Self::Error> {
		if binding != self.binding || self.revoked.is_cancelled() {
			return Err(io::ErrorKind::ConnectionAborted.into());
		}
		Ok(())
	}

	fn send(
		&mut self,
		binding: PeerBinding,
		bytes: &[u8],
	) -> Result<PacketDisposition, Self::Error> {
		self.check(binding)?;
		assert!(!self.blocked, "the driver retried before readiness");
		if self.block_once {
			self.block_once = false;
			self.blocked = true;
			return Ok(PacketDisposition::Backpressure);
		}
		let mut frame = Packet {
			bytes: [0; INNER_MTU],
			len: bytes.len(),
		};
		frame.bytes[..frame.len].copy_from_slice(bytes);
		match self.sender.try_send(frame) {
			Ok(()) => Ok(PacketDisposition::Accepted),
			Err(mpsc::error::TrySendError::Full(_)) => {
				self.blocked = true;
				Ok(PacketDisposition::Backpressure)
			}
			// UDP can submit after the receiver's application has already closed.
			Err(mpsc::error::TrySendError::Closed(_)) => Ok(PacketDisposition::Accepted),
		}
	}

	async fn wait(
		&mut self,
		interest: PacketInterest,
		output: &mut [u8; INNER_MTU],
	) -> Result<PacketEvent, Self::Error> {
		self.waited.notify_one();
		tokio::select! {
			() = self.revoked.cancelled() => Err(io::ErrorKind::ConnectionAborted.into()),
			frame = self.receiver.recv(), if interest.receive => {
				let frame = frame.ok_or(io::ErrorKind::BrokenPipe)?;
				output[..frame.len].copy_from_slice(&frame.bytes[..frame.len]);
				Ok(PacketEvent::Received(frame.len))
			}
			reservation = self.sender.reserve(), if interest.writable => {
				drop(reservation);
				// An absent receiver no longer backpressures datagram submission.
				self.blocked = false;
				self.writable_events.fetch_add(1, Ordering::SeqCst);
				Ok(PacketEvent::Writable)
			}
		}
	}
}

fn endpoints(binding: PeerBinding) -> (TestPackets, TestPackets) {
	let (a_send, b_receive) = mpsc::channel(1);
	let (b_send, a_receive) = mpsc::channel(1);
	let create = |sender, receiver| TestPackets {
		sender,
		receiver,
		binding,
		revoked: CancellationToken::new(),
		waited: Arc::new(Notify::new()),
		writable_events: Arc::new(AtomicUsize::new(0)),
		block_once: true,
		blocked: false,
	};
	(create(a_send, a_receive), create(b_send, b_receive))
}

fn into_async(tcp: InnerTcp) -> (InnerTcpStream, TcpPump) {
	let route = RouteRevocation::new(tcp.binding());
	tcp.into_async(route).unwrap()
}

async fn exchange(stream: &mut InnerTcpStream, output: &[u8]) -> io::Result<Vec<u8>> {
	let (mut read, mut write) = tokio::io::split(stream);
	let mut input = Vec::new();
	tokio::try_join!(
		async {
			write.write_all(output).await?;
			write.shutdown().await
		},
		async {
			read.read_to_end(&mut input).await?;
			Ok(())
		},
	)?;
	Ok(input)
}

async fn bidirectional(flow: TcpFlow) {
	let (first, second) = pair(flow);
	let (first_packets, second_packets) = endpoints(first.binding());
	// Keep the synthetic path open until both flow drivers have finished.
	let _path = (first_packets.sender.clone(), second_packets.sender.clone());
	let first_ready = Arc::clone(&first_packets.writable_events);
	let second_ready = Arc::clone(&second_packets.writable_events);
	let (mut first_stream, first_pump) = into_async(first);
	let (mut second_stream, second_pump) = into_async(second);
	let outgoing = vec![71; 3 * PIPE_BYTES + 17];
	let incoming = vec![53; 4 * PIPE_BYTES + 31];

	let (first_driver, second_driver, first_data, second_data) =
		timeout(Duration::from_secs(16), async {
			tokio::join!(
				first_pump.run(first_packets),
				second_pump.run(second_packets),
				exchange(&mut first_stream, &outgoing),
				exchange(&mut second_stream, &incoming),
			)
		})
		.await
		.unwrap();
	first_driver.unwrap();
	second_driver.unwrap();
	assert_eq!(first_data.unwrap(), incoming);
	assert_eq!(second_data.unwrap(), outgoing);
	assert!(first_ready.load(Ordering::SeqCst) > 0);
	assert!(second_ready.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn supervised_pumps_move_bytes_and_close_both_directions() {
	tokio::join!(bidirectional(ipv4_flow()), bidirectional(ipv6_flow()));
}

#[tokio::test]
async fn dropping_unpolled_driver_fences_reads_writes_and_shutdown() {
	let flow = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let (mut stream, pump) = into_async(flow);
	let (packets, _peer) = endpoints(pump.tcp.binding());
	drop(pump.run(packets));
	assert_eq!(
		stream.read_u8().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
	assert_eq!(
		stream.write(b"late").await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
	assert_eq!(
		stream.shutdown().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}

#[tokio::test]
async fn revocation_wakes_an_idle_stream() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let (packets, _peer) = endpoints(tcp.binding());
	let revocation = packets.revoked.clone();
	let waiting = Arc::clone(&packets.waited);
	let (mut stream, pump) = into_async(tcp);
	let (result, stream_error, ()) = timeout(Duration::from_secs(2), async {
		tokio::join!(pump.run(packets), stream.read_u8(), async move {
			waiting.notified().await;
			revocation.cancel();
		})
	})
	.await
	.unwrap();
	assert!(
		matches!(result, Err(PumpError::Route(error)) if error.kind() == io::ErrorKind::ConnectionAborted)
	);
	assert_eq!(
		stream_error.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}

#[tokio::test]
async fn dropping_application_cancels_driver_without_a_spawned_task() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let (packets, _peer) = endpoints(tcp.binding());
	let (stream, pump) = into_async(tcp);
	drop(stream);
	assert!(matches!(pump.run(packets).await, Err(PumpError::Cancelled)));
}

#[tokio::test]
async fn cancellation_refuses_already_buffered_pipe_bytes() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let (mut stream, mut pump) = into_async(tcp);
	pump.pipe
		.write_all(b"buffered before revocation")
		.await
		.unwrap();
	drop(pump);

	let mut output = [42; 24];
	let error = stream.read(&mut output).await.unwrap_err();
	assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
	assert_eq!(output, [42; 24]);
}

#[tokio::test]
async fn independent_pipe_capacity_and_driver_drop_refuse_further_writes() {
	let (mut stream, pump) = into_async(InnerTcp::connect(ipv4_flow(), 19).unwrap());
	let remaining = [3; PIPE_BYTES + 1];
	assert_eq!(stream.write(&remaining).await.unwrap(), PIPE_BYTES);
	let blocked = timeout(Duration::from_millis(5), stream.write(&[7])).await;
	assert!(blocked.is_err(), "the unpolled pipe must be full");
	drop(pump);
	assert_eq!(
		stream.write(&[8]).await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}

struct NeverWritable {
	binding: PeerBinding,
	waiting: Arc<Notify>,
	offers: Arc<AtomicUsize>,
}

impl PacketIo for NeverWritable {
	type Error = io::Error;

	fn check(&mut self, binding: PeerBinding) -> Result<(), Self::Error> {
		assert!(binding == self.binding);
		Ok(())
	}

	fn send(
		&mut self,
		binding: PeerBinding,
		_packet: &[u8],
	) -> Result<PacketDisposition, Self::Error> {
		self.check(binding)?;
		self.offers.fetch_add(1, Ordering::Relaxed);
		Ok(PacketDisposition::Backpressure)
	}

	async fn wait(
		&mut self,
		interest: PacketInterest,
		_packet: &mut [u8; INNER_MTU],
	) -> Result<PacketEvent, Self::Error> {
		assert!(interest.writable);
		self.waiting.notify_one();
		std::future::pending().await
	}
}

#[tokio::test]
async fn independent_drop_of_polled_driver_under_backpressure_does_not_retry() {
	let tcp = InnerTcp::connect(ipv4_flow(), 31).unwrap();
	let waiting = Arc::new(Notify::new());
	let offers = Arc::new(AtomicUsize::new(0));
	let io = NeverWritable {
		binding: tcp.binding(),
		waiting: waiting.clone(),
		offers: offers.clone(),
	};
	let (mut stream, pump) = into_async(tcp);
	{
		let run = pump.run(io);
		tokio::pin!(run);
		tokio::select! {
			result = &mut run => panic!("the pump must still be blocked: {result:?}"),
			() = waiting.notified() => {}
			() = tokio::time::sleep(Duration::from_secs(2)) => panic!("no readiness wait observed"),
		}
	}
	assert_eq!(offers.load(Ordering::Relaxed), 1);
	assert_eq!(
		stream.read_u8().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
	assert_eq!(offers.load(Ordering::Relaxed), 1);
}

#[path = "tests/close.rs"]
mod close;
#[path = "tests/lifecycle.rs"]
mod lifecycle;
