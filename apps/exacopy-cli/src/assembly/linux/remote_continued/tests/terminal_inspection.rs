use exacopy_journal::frame::{FrameKind, FrameReader};
use exacopy_journal::remote_download::RemoteBootstrapTrust;
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};

use crate::assembly::linux::remote_journal::witnessed_inspection::{
	WitnessedInspectionError, terminal_history,
};

use super::{ChainHead, field};

pub(super) fn check(
	live_bytes: &[u8],
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) {
	let replay = replay_remote_witnessed_closeout(live_bytes, trust, selection).unwrap();
	let accepted = terminal_history(&replay, live_bytes.len() as u64).unwrap();
	assert!(matches!(
		accepted.outcome(),
		RemoteWitnessedOutcome::Submitted(_)
	));
	assert!(matches!(
		terminal_history(&replay, live_bytes.len() as u64 + 1),
		Err(WitnessedInspectionError::History { issue: None, .. })
	));

	let recovered_bytes = field(
		vector!("remote_continuation/witnessed_replay.hex"),
		"recovered-published",
	);
	let replay =
		replay_remote_witnessed_closeout(recovered_bytes.as_slice(), trust, selection).unwrap();
	let accepted = terminal_history(&replay, recovered_bytes.len() as u64).unwrap();
	assert!(matches!(
		accepted.outcome(),
		RemoteWitnessedOutcome::Recovered { .. }
	));

	let mut frames = FrameReader::new(live_bytes, ChainHead::start());
	let ready_end = loop {
		let frame = frames.next_frame().unwrap().unwrap();
		if frame.kind() == FrameKind::RemoteReceiptReady {
			break frames.offset() as usize;
		}
	};
	let mut trailing = live_bytes.to_vec();
	trailing.push(0);
	for bytes in [
		&live_bytes[..ready_end],
		&live_bytes[..live_bytes.len() - 1],
		&trailing,
	] {
		let replay = replay_remote_witnessed_closeout(bytes, trust, selection).unwrap();
		assert!(matches!(
			terminal_history(&replay, bytes.len() as u64),
			Err(WitnessedInspectionError::History { .. })
		));
	}
}
