use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::sync::oneshot;

pub(super) enum ShutdownConfirmation {
	Waiting(oneshot::Receiver<()>),
	Complete,
	Unconfirmed,
}

impl ShutdownConfirmation {
	pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		if let Self::Waiting(receiver) = self {
			*self = match ready!(Pin::new(receiver).poll(cx)) {
				Ok(()) => Self::Complete,
				Err(_) => Self::Unconfirmed,
			};
		}
		if matches!(self, Self::Complete) {
			Poll::Ready(Ok(()))
		} else {
			Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()))
		}
	}
}
