use std::io::Read as _;

use exacopy_journal::frame::{FrameKind, FrameReader};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::replay::replay_remote_witnessed_closeout;

use super::super::witness::publication::receipt::LiveReceipt;
use super::field;

pub(super) fn check_exact_receipt_successors(
	full: &[u8],
	live: &LiveReceipt<'_, '_>,
	mut frames: FrameReader<&[u8]>,
) {
	let kind42 = frames.next_frame().unwrap().unwrap();
	assert_eq!(kind42.kind(), FrameKind::RemoteReceiptReady);
	let ready_end = frames.offset() as usize;
	let kind18 = frames.next_frame().unwrap().unwrap();
	assert_eq!(kind18.kind(), FrameKind::ReceiptCommitted);
	let committed_end = frames.offset() as usize;

	let replay =
		replay_remote_witnessed_closeout(&full[..ready_end], live.trust, live.selection).unwrap();
	let receipt = replay.receipt_ready().unwrap().receipt();
	let durable_end = live.durable.offset as usize;
	let mut pending = live.prepare_pending(&full[..durable_end], receipt).unwrap();
	assert_eq!(pending.proposal.encoded(), &full[durable_end..ready_end]);
	assert_eq!(
		pending.bytes,
		field(
			vector!("remote_continuation/witnessed_replay.hex"),
			"receipt"
		)
	);
	let ready = live
		.confirm_pending(
			full[..durable_end].chain(pending.proposal.encoded()),
			&pending,
		)
		.unwrap();
	assert_eq!(
		ready.boundary(),
		RemoteReplayBoundary {
			head: kind42.head(),
			offset: ready_end as u64,
		}
	);
	assert!(
		live.confirm_pending(&full[..ready_end - 1], &pending)
			.is_err()
	);
	assert!(
		live.prepare_pending(&full[..durable_end], live.target)
			.is_err()
	);

	// Equal recorded digest and inode do not substitute for exact receipt bytes.
	pending.bytes[0] ^= 1;
	assert!(
		live.prepare_commit(&full[..ready_end], &pending, ready)
			.is_err()
	);
	pending.bytes[0] ^= 1;

	let committed = live
		.prepare_commit(&full[..ready_end], &pending, ready)
		.unwrap();
	assert_eq!(committed.encoded(), &full[ready_end..committed_end]);
	live.confirm_commit(
		full[..ready_end].chain(committed.encoded()),
		&committed,
		ready,
	)
	.unwrap();
	assert!(
		live.confirm_commit(&full[..committed_end - 1], &committed, ready)
			.is_err()
	);
}
