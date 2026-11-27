use std::future::poll_fn;
use std::pin::Pin;
use std::task::Poll;

use tokio::io::AsyncWrite;
use tokio::sync::oneshot;

use super::*;

#[tokio::test]
async fn confirmed_shutdown_waits_for_queued_data_and_the_peer_fin() {
	let (first, second) = pair(ipv4_flow());
	let (first_packets, second_packets) = endpoints(first.binding());
	let _paths = (first_packets.sender.clone(), second_packets.sender.clone());
	let (mut client, mut first_pump) = into_async(first);
	let (mut peer, second_pump) = into_async(second);
	first_pump.confirm_shutdown(&mut client);
	let (received, observe) = oneshot::channel();
	let (allow_fin, ready) = oneshot::channel();
	let data = vec![41; PIPE_BYTES];
	let (first, second, _, _) = timeout(Duration::from_secs(15), async {
		tokio::join!(
			first_pump.run(first_packets),
			second_pump.run(second_packets),
			async {
				client.write_all(&data).await.unwrap();
				poll_fn(|cx| {
					assert!(Pin::new(&mut client).poll_shutdown(cx).is_pending());
					Poll::Ready(())
				})
				.await;
				observe.await.unwrap();
				poll_fn(|cx| {
					assert!(Pin::new(&mut client).poll_shutdown(cx).is_pending());
					Poll::Ready(())
				})
				.await;
				allow_fin.send(()).unwrap();
				client.shutdown().await.unwrap();
				// Repeated AsyncWrite shutdown polls are idempotent.
				client.shutdown().await.unwrap();
				assert!(client.write_u8(0).await.is_err());
			},
			async {
				let mut drained = Vec::new();
				peer.read_to_end(&mut drained).await.unwrap();
				assert_eq!(drained, data);
				received.send(()).unwrap();
				ready.await.unwrap();
				peer.shutdown().await.unwrap();
			}
		)
	})
	.await
	.unwrap();
	first.unwrap();
	second.unwrap();
}

#[tokio::test]
async fn revocation_during_shutdown_fences_old_egress_and_cannot_confirm() {
	let (first, _second) = pair(ipv4_flow());
	let (packets, mut peer_packets) = endpoints(first.binding());
	let route = RouteRevocation::new(first.binding());
	let (mut stream, mut pump) = first.into_async(route.clone()).unwrap();
	pump.confirm_shutdown(&mut stream);
	poll_fn(|cx| {
		assert!(Pin::new(&mut stream).poll_shutdown(cx).is_pending());
		Poll::Ready(())
	})
	.await;
	route.revoke();
	let (driver, close) = tokio::join!(pump.run(packets), stream.shutdown());
	assert!(matches!(driver, Err(PumpError::RouteRevoked)));
	assert!(peer_packets.receiver.try_recv().is_err());
	assert_eq!(close.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
	assert_eq!(
		stream.write_u8(0).await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}

#[tokio::test]
async fn a_cancelled_driver_does_not_confirm_the_requested_close() {
	let (first, _) = pair(ipv4_flow());
	let (mut stream, mut pump) = into_async(first);
	pump.confirm_shutdown(&mut stream);
	poll_fn(|cx| {
		assert!(Pin::new(&mut stream).poll_shutdown(cx).is_pending());
		Poll::Ready(())
	})
	.await;
	drop(pump);
	assert_eq!(
		stream.shutdown().await.unwrap_err().kind(),
		io::ErrorKind::ConnectionAborted
	);
}
