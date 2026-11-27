use exacopy_journal::frame::{FrameKind, FrameReader};
use exacopy_journal::remote_download::RemoteBootstrapTrust;
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};

use crate::assembly::linux::remote_journal::witnessed_inspection::{
	WitnessedInspectionError, intent_history, terminal_history, verify_public_digest,
};

use super::{ChainHead, field};

pub(super) fn check(
	live_bytes: &[u8],
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) {
	check_publish_intent(live_bytes, trust, selection);
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

fn check_publish_intent(
	bytes: &[u8],
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) {
	let mut frames = FrameReader::new(bytes, ChainHead::start());
	let (intent, offset) = loop {
		let frame = frames.next_frame().unwrap().unwrap();
		if frame.kind() == FrameKind::PublishIntent {
			break (frame.head(), frames.offset() as usize);
		}
	};
	let replay = replay_remote_witnessed_closeout(&bytes[..offset], trust, selection).unwrap();
	let verified = intent_history(&replay, offset as u64).unwrap();
	assert_eq!(verified.boundary().head, intent);
	assert_eq!(verified.stage().file, verified.witness().binding().stage());
	let mut scratch = [0; 2];
	for (data, equal) in [(b"ABCD", true), (b"ABcD", false)] {
		let result = verify_public_digest(&verified, &mut scratch, |offset, output| {
			let start = usize::try_from(offset).unwrap();
			output.copy_from_slice(&data[start..start + output.len()]);
			Ok(())
		});
		if equal {
			result.unwrap();
		} else {
			assert!(matches!(
				result,
				Err(WitnessedInspectionError::PublicDigestMismatch)
			));
		}
	}
	assert!(replay.observed_outcome().is_none());
	assert!(intent_history(&replay, offset as u64 + 1).is_err());
	assert!(terminal_history(&replay, offset as u64).is_err());
	for cut in [&bytes[..offset - 1], bytes] {
		let replay = replay_remote_witnessed_closeout(cut, trust, selection).unwrap();
		assert!(intent_history(&replay, cut.len() as u64).is_err());
	}
}
