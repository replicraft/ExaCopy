use russh::ChannelMsg;

use crate::Error;

const MAX_WINDOW_ADJUSTMENTS: usize = 8;

/// Waits for the explicit subsystem reply. OpenSSH can send a channel window
/// adjustment first when it connects the subsystem's I/O.
pub(super) async fn confirm(
	mut receive: impl AsyncFnMut() -> Option<ChannelMsg>,
) -> Result<(), Error> {
	for _ in 0..=MAX_WINDOW_ADJUSTMENTS {
		match receive().await {
			Some(ChannelMsg::Success) => return Ok(()),
			Some(ChannelMsg::WindowAdjusted { .. }) => {}
			_ => return Err(Error::Subsystem),
		}
	}
	Err(Error::Subsystem)
}

#[cfg(test)]
mod tests {
	use russh::ChannelMsg;

	use super::{MAX_WINDOW_ADJUSTMENTS, confirm};
	use crate::Error;

	#[tokio::test]
	async fn window_updates_leave_the_request_pending_until_explicit_success() {
		let mut updates = (0..MAX_WINDOW_ADJUSTMENTS)
			.map(|_| ChannelMsg::WindowAdjusted { new_size: 32768 })
			.chain([ChannelMsg::Success]);
		assert!(confirm(async || updates.next()).await.is_ok());
	}

	#[tokio::test]
	async fn unsolicited_data_failures_and_excess_window_updates_refuse_setup() {
		let messages = [
			Some(ChannelMsg::Failure),
			Some(ChannelMsg::Data {
				data: vec![1].into(),
			}),
			Some(ChannelMsg::Eof),
			None,
		];
		for message in messages {
			let mut replies = [message, Some(ChannelMsg::Success)].into_iter();
			assert!(matches!(
				confirm(async || replies.next().flatten()).await,
				Err(Error::Subsystem),
			));
		}
		assert!(matches!(
			confirm(async || Some(ChannelMsg::WindowAdjusted { new_size: 32768 })).await,
			Err(Error::Subsystem),
		));
	}
}
