use std::task::{Wake, Waker};

use super::*;

const SCHEDULER_MARGIN: Duration = Duration::from_secs(4);

#[test]
fn different_or_already_revoked_route_signals_are_refused() {
	let mut other_flow = ipv4_flow();
	other_flow.binding.revision = [9; 32];
	let other = RouteRevocation::new(other_flow.binding);
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	assert!(matches!(
		tcp.into_async(other),
		Err(TcpError::RouteMismatch)
	));

	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let route = RouteRevocation::new(tcp.binding());
	route.revoke();
	assert!(matches!(tcp.into_async(route), Err(TcpError::Closed)));
}

#[test]
fn closing_fenced_or_previously_advanced_flows_cannot_expose_new_streams() {
	let mut fenced = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let route = RouteRevocation::new(fenced.binding());
	fenced.fence();
	assert!(matches!(fenced.into_async(route), Err(TcpError::Closed)));

	let mut closing = established_pair().0;
	let route = RouteRevocation::new(closing.binding());
	closing.close_send().unwrap();
	assert!(matches!(closing.into_async(route), Err(TcpError::Closed)));

	let mut advanced = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let route = RouteRevocation::new(advanced.binding());
	advanced.poll(Duration::from_millis(1)).unwrap();
	assert!(matches!(advanced.into_async(route), Err(TcpError::Clock)));
}

#[test]
fn an_ordinary_peer_abort_fences_the_flow_instead_of_completing_gracefully() {
	use crate::stack::TcpState;

	let (mut client, mut peer) = established_pair();
	peer.socket_mut().unwrap().abort();
	assert_eq!(peer.ingress(&[]), Err(TcpError::Closed));
	offer(&mut peer, &mut client);
	assert_eq!(client.poll(Duration::ZERO), Err(TcpError::Reset));
	assert_eq!(client.state(), TcpState::Closed);
	assert_eq!(client.ingress(&[]), Err(TcpError::Closed));
}

#[tokio::test]
async fn direct_route_revocation_refuses_buffered_bytes_without_polling_the_pump() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let route = RouteRevocation::new(tcp.binding());
	let (mut stream, mut pump) = tcp.into_async(route.clone()).unwrap();
	pump.pipe
		.write_all(b"buffered for the old route")
		.await
		.unwrap();
	route.revoke();

	let mut output = [42; 8];
	assert_eq!(
		stream.read(&mut output).await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
	assert_eq!(output, [42; 8]);
	assert_eq!(
		stream.write(b"late").await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
	assert_eq!(
		stream.flush().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
	assert_eq!(
		stream.shutdown().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
	assert!(pump.signals.shutdown.borrow().is_none());

	let (packets, _peer) = endpoints(pump.tcp.binding());
	assert!(matches!(
		pump.run(packets).await,
		Err(PumpError::RouteRevoked)
	));
}

#[tokio::test]
async fn direct_route_revocation_wakes_a_parked_pump_and_reader() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let route = RouteRevocation::new(tcp.binding());
	let (packets, _peer) = endpoints(tcp.binding());
	let waited = Arc::clone(&packets.waited);
	let (mut stream, pump) = tcp.into_async(route.clone()).unwrap();

	let (pump_result, read, ()) = timeout(Duration::from_secs(2), async {
		tokio::join!(pump.run(packets), stream.read_u8(), async move {
			waited.notified().await;
			route.revoke();
		})
	})
	.await
	.unwrap();

	assert!(matches!(pump_result, Err(PumpError::RouteRevoked)));
	assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
}

struct ObservePipeWake {
	fence: CancellationToken,
	first: AtomicUsize,
}

impl Wake for ObservePipeWake {
	fn wake(self: Arc<Self>) {
		self.wake_by_ref();
	}

	fn wake_by_ref(self: &Arc<Self>) {
		let observed = if self.fence.is_cancelled() { 2 } else { 1 };
		let _ = self
			.first
			.compare_exchange(0, observed, Ordering::SeqCst, Ordering::SeqCst);
	}
}

fn watch_raw_pipe_close(stream: &mut InnerTcpStream, pump: &TcpPump) -> Arc<ObservePipeWake> {
	let witness = Arc::new(ObservePipeWake {
		fence: pump.signals.cancelled.clone(),
		first: AtomicUsize::new(0),
	});
	let waker = Waker::from(Arc::clone(&witness));
	let mut cx = Context::from_waker(&waker);
	// Watch the pipe directly so a cancellation wake cannot satisfy the assertion.
	let mut scratch = [0];
	assert!(
		Pin::new(&mut stream.pipe)
			.poll_read(&mut cx, &mut ReadBuf::new(&mut scratch))
			.is_pending()
	);
	witness
}

#[tokio::test]
async fn failing_driver_sets_fence_before_the_raw_pipe_wakes() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let (packets, _peer) = endpoints(tcp.binding());
	packets.revoked.cancel();
	let (mut stream, pump) = into_async(tcp);
	let witness = watch_raw_pipe_close(&mut stream, &pump);

	assert!(matches!(pump.run(packets).await, Err(PumpError::Route(_))));
	assert_eq!(witness.first.load(Ordering::SeqCst), 2);
	assert_eq!(
		stream.read_u8().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}

#[tokio::test]
async fn dropping_a_polled_driver_sets_fence_before_the_raw_pipe_wakes() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let waiting = Arc::new(Notify::new());
	let offers = Arc::new(AtomicUsize::new(0));
	let packets = NeverWritable {
		binding: tcp.binding(),
		waiting: Arc::clone(&waiting),
		offers,
	};
	let (mut stream, pump) = into_async(tcp);
	let witness = watch_raw_pipe_close(&mut stream, &pump);
	{
		let run = pump.run(packets);
		tokio::pin!(run);
		tokio::select! {
			result = &mut run => panic!("driver should remain parked: {result:?}"),
			() = waiting.notified() => {},
			() = tokio::time::sleep(Duration::from_secs(2)) => panic!("driver did not wait"),
		}
		assert_eq!(witness.first.load(Ordering::SeqCst), 0);
	}
	assert_eq!(witness.first.load(Ordering::SeqCst), 2);
	assert_eq!(
		stream.read_u8().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}

#[tokio::test]
async fn shutdown_signal_keeps_the_first_admitted_instant() {
	let tcp = InnerTcp::connect(ipv4_flow(), 1).unwrap();
	let (mut stream, pump) = into_async(tcp);
	stream.write_all(&[1; PIPE_BYTES]).await.unwrap();
	stream.shutdown().await.unwrap();
	let first = (*pump.signals.shutdown.borrow()).expect("a buffered shutdown is still admitted");
	tokio::task::yield_now().await;
	stream.shutdown().await.unwrap();
	assert_eq!(*pump.signals.shutdown.borrow(), Some(first));
}

#[tokio::test]
#[ignore = "waits for the actual 20-second graceful drain deadline"]
async fn blocked_egress_and_queued_app_bytes_still_have_a_shutdown_deadline() {
	let mut tcp = established_pair().0;
	let queued = [5; crate::stack::STREAM_BUFFER_BYTES];
	assert_eq!(tcp.write(&queued).unwrap(), queued.len());
	let offers = Arc::new(AtomicUsize::new(0));
	let waiting = Arc::new(Notify::new());
	let packets = NeverWritable {
		binding: tcp.binding(),
		waiting: Arc::clone(&waiting),
		offers: Arc::clone(&offers),
	};
	let (mut stream, pump) = into_async(tcp);
	stream.write_all(&[1; PIPE_BYTES]).await.unwrap();
	let (result, started) = timeout(drive::CLOSE_LIMIT + SCHEDULER_MARGIN, async {
		tokio::join!(pump.run(packets), async {
			waiting.notified().await;
			let started = Instant::now();
			stream.shutdown().await.unwrap();
			started
		})
	})
	.await
	.unwrap();
	assert!(matches!(result, Err(PumpError::Deadline)));
	assert!(started.elapsed() >= drive::CLOSE_LIMIT);
	assert_eq!(offers.load(Ordering::Relaxed), 1);
	assert_eq!(
		stream.read_u8().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}

fn offer(sender: &mut InnerTcp, receiver: &mut InnerTcp) {
	if sender.poll(Duration::ZERO).unwrap() == crate::stack::PollHint::Egress {
		sender
			.egress(|binding, packet| {
				assert!(binding == receiver.binding());
				receiver.ingress(packet)?;
				Ok::<_, TcpError>(PacketDisposition::Accepted)
			})
			.unwrap();
	}
}

fn established_pair() -> (InnerTcp, InnerTcp) {
	use crate::stack::TcpState;

	let (mut client, mut server) = pair(ipv4_flow());
	for _ in 0..8 {
		offer(&mut client, &mut server);
		offer(&mut server, &mut client);
		if client.state() == TcpState::Writable && server.state() == TcpState::Writable {
			return (client, server);
		}
	}
	panic!("the pair could not start a bounded established-flow test");
}

#[tokio::test]
#[ignore = "waits for the actual 20-second graceful drain deadline"]
async fn peer_receive_only_half_close_cannot_postpone_the_shutdown_deadline() {
	let (client, server) = pair(ipv4_flow());
	let (client_packets, server_packets) = endpoints(client.binding());
	let _path = (client_packets.sender.clone(), server_packets.sender.clone());
	let (mut writer, client_pump) = into_async(client);
	let (mut remote, server_pump) = into_async(server);
	writer.write_u8(17).await.unwrap();
	let started = Instant::now();
	writer.shutdown().await.unwrap();
	let stop = CancellationToken::new();

	let (client_result, (), ()) = timeout(drive::CLOSE_LIMIT + SCHEDULER_MARGIN, async {
		tokio::join!(
			async {
				let result = client_pump.run(client_packets).await;
				stop.cancel();
				result
			},
			async {
				tokio::select! {
					() = stop.cancelled() => {},
					result = server_pump.run(server_packets) => panic!("peer should stay live: {result:?}"),
				}
			},
			async {
				assert_eq!(remote.read_u8().await.unwrap(), 17);
				assert_eq!(remote.read(&mut [0]).await.unwrap(), 0);
				// Keep the peer's send half open for the entire final deadline test.
				stop.cancelled().await;
			}
		)
	})
	.await
	.unwrap();
	assert!(matches!(client_result, Err(PumpError::Deadline)));
	assert!(started.elapsed() >= drive::CLOSE_LIMIT);
	assert_eq!(
		writer.read_u8().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}
