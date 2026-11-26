use std::sync::{Arc, Mutex};

use exacopy_ssh::SshSessionCancellation;
use tokio::runtime::Runtime;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::assembly::linux::remote_download::RemoteGrant;
use crate::remote_report::RemoteFailureKind as Failure;

#[derive(Default)]
pub(super) struct Interrupt {
	inner: Mutex<Observed>,
	change: Notify,
}

#[derive(Default)]
struct Observed {
	interrupted: bool,
	grant: Option<Arc<RemoteGrant>>,
	route: Option<SshSessionCancellation>,
}

impl Interrupt {
	pub(super) fn register(
		runtime: &Runtime,
		interrupt: Arc<Self>,
	) -> std::io::Result<JoinHandle<()>> {
		let mut event = {
			let _context = runtime.enter();
			signal(SignalKind::interrupt())?
		};
		Ok(runtime.spawn(async move {
			if event.recv().await.is_some() {
				interrupt.cancel();
			}
		}))
	}

	fn cancel(&self) {
		let (grant, route) = {
			let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
			state.interrupted = true;
			(state.grant.take(), state.route.take())
		};
		if let Some(grant) = grant {
			grant.revoke();
		}
		if let Some(route) = route {
			route.cancel();
		}
		self.change.notify_waiters();
	}

	pub(super) fn grant(&self, grant: &Arc<RemoteGrant>) -> Result<(), Failure> {
		let mut state = self.inner.lock().map_err(|_| Failure::Io)?;
		if state.interrupted {
			return Err(Failure::Cancelled);
		}
		state.grant = Some(Arc::clone(grant));
		Ok(())
	}

	pub(super) fn route(&self, route: SshSessionCancellation) -> Result<(), Failure> {
		let mut state = self.inner.lock().map_err(|_| Failure::Io)?;
		if state.interrupted {
			drop(state);
			route.cancel();
			return Err(Failure::Cancelled);
		}
		state.route = Some(route);
		Ok(())
	}

	pub(super) fn cancelled(&self) -> bool {
		self.inner.lock().is_ok_and(|state| state.interrupted)
	}

	pub(super) fn check(&self) -> Result<(), Failure> {
		if self.inner.lock().map_err(|_| Failure::Io)?.interrupted {
			return Err(Failure::Cancelled);
		}
		Ok(())
	}

	pub(super) async fn wait(&self) {
		let wake = self.change.notified();
		tokio::pin!(wake);
		wake.as_mut().enable();
		if !self.cancelled() {
			wake.await;
		}
	}
}
