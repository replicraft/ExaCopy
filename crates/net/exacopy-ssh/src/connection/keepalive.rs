use std::time::Duration;

use russh::client;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout};
use tokio_util::sync::DropGuard;
use tokio_util::task::AbortOnDropHandle;

use super::HostCheck;
use crate::Error;

const PROBE_INTERVAL: Duration = Duration::from_secs(5);
const REPLY_DEADLINE: Duration = Duration::from_secs(10);

pub(in crate::connection) fn supervise(
	mut connection: client::Handle<HostCheck>,
	fence: DropGuard,
) -> (
	impl Future<Output = Result<(), Error>> + Send,
	DropGuard,
	oneshot::Sender<oneshot::Sender<()>>,
) {
	let token = fence.disarm();
	let session_fence = token.clone().drop_guard();
	let driver_fence = token.drop_guard();
	let (disconnect, request) = oneshot::channel::<oneshot::Sender<()>>();
	let task = AbortOnDropHandle::new(tokio::spawn(async move {
		let _fence = driver_fence;
		let acknowledged = tokio::select! {
			biased;
			result = probe_peer(&mut connection) => return result,
			request = requested_disconnect(request) => request,
		};
		connection
			.disconnect(russh::Disconnect::ByApplication, "", "")
			.await?;
		let _ = acknowledged.send(());
		connection.await
	}));
	(
		async move { task.await.map_err(|_| Error::Closed)? },
		session_fence,
		disconnect,
	)
}

async fn requested_disconnect(
	request: oneshot::Receiver<oneshot::Sender<()>>,
) -> oneshot::Sender<()> {
	match request.await {
		Ok(request) => request,
		Err(_) => std::future::pending().await,
	}
}

async fn probe_peer(connection: &mut client::Handle<HostCheck>) -> Result<(), Error> {
	loop {
		tokio::select! {
			biased;
			result = &mut *connection => return result,
			() = sleep(PROBE_INTERVAL) => {}
		}
		// An ordinary inbound packet must not complete the probe or allow a
		// second global request to queue behind an unanswered first one.
		let reply = timeout(REPLY_DEADLINE, connection.send_ping()).await;
		// Russh's ping also returns when its response sender is dropped.
		// Preserve the actual connection result if the driver has closed.
		if connection.is_closed() {
			return connection.await;
		}
		reply.map_err(|_| russh::Error::KeepaliveTimeout)??;
	}
}
