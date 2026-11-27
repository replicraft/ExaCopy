use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::frame::{FrameKind, FrameReader};
use exacopy_journal::remote_download::RemoteBootstrapTrust;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	RemoteCommittedReceiptInspection, RemoteWitnessedCloseoutReplay,
	RemoteWitnessedReplayPhase as Phase, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};

use crate::assembly::linux::remote_journal::ReplayIssue;
use crate::assembly::linux::remote_journal::witnessed_inspection::{
	WitnessedInspectionError, first_unretired_witnessed_pass, intent_history,
	receipt_ready_history, selected_terminal_history, terminal_history, verify_public_digest,
	verify_receipt_ready_bytes,
};

use super::{ChainHead, field, hex};

pub(super) fn check(
	live_bytes: &[u8],
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) {
	check_publish_intent(live_bytes, trust, selection);
	check_first_pass(trust, selection);
	let replay = replay_remote_witnessed_closeout(live_bytes, trust, selection).unwrap();
	let accepted = terminal_history(&replay, live_bytes.len() as u64).unwrap();
	assert!(matches!(
		accepted.outcome(),
		RemoteWitnessedOutcome::Submitted(_)
	));
	check_terminal_selection(&replay, &accepted, live_bytes.len() as u64);
	assert!(matches!(
		terminal_history(&replay, live_bytes.len() as u64 + 1),
		Err(WitnessedInspectionError::History { issue: None, .. })
	));

	let vector = vector!("remote_continuation/witnessed_replay.hex");
	let recovered_bytes = field(vector, "recovered-published");
	let replay =
		replay_remote_witnessed_closeout(recovered_bytes.as_slice(), trust, selection).unwrap();
	let accepted = terminal_history(&replay, recovered_bytes.len() as u64).unwrap();
	assert!(matches!(
		accepted.outcome(),
		RemoteWitnessedOutcome::Recovered { .. }
	));
	assert!(first_unretired_witnessed_pass(&replay));
	assert!(matches!(
		selected_terminal_history(
			&replay,
			recovered_bytes.len() as u64,
			accepted.boundary(),
			accepted.record().digest(),
		),
		Err(WitnessedInspectionError::SelectionMismatch)
	));

	let live_receipt = field(vector, "receipt");
	let recovered_receipt = field(vector, "recovered-receipt");
	let ready = check_receipt_ready(
		live_bytes,
		&live_receipt,
		&recovered_receipt,
		trust,
		selection,
	);
	check_receipt_ready(
		&recovered_bytes,
		&recovered_receipt,
		&live_receipt,
		trust,
		selection,
	);

	let bad_commit = field(vector, "wrong-committed-inode");
	let replay = replay_remote_witnessed_closeout(bad_commit.as_slice(), trust, selection).unwrap();
	assert!(matches!(
		receipt_ready_history(&replay, ready.offset),
		Err(WitnessedInspectionError::History {
			phase: Phase::ReceiptReadyRequiresInspection,
			boundary,
			issue: Some(ReplayIssue::Refused),
		}) if boundary == ready
	));

	let ready_end = usize::try_from(ready.offset).unwrap();
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

fn check_terminal_selection(
	replay: &RemoteWitnessedCloseoutReplay,
	accepted: &RemoteCommittedReceiptInspection<'_>,
	native_end: u64,
) {
	let boundary = accepted.boundary();
	let digest = accepted.record().digest();
	let inspected = selected_terminal_history(replay, native_end, boundary, digest).unwrap();
	assert_eq!(inspected.boundary(), boundary);
	assert_eq!(inspected.record().digest(), digest);

	let mut wrong_head_digest = boundary.head.digest();
	wrong_head_digest[0] ^= 1;
	let wrong_head = ChainHead::after(boundary.head.sequence(), wrong_head_digest).unwrap();
	let mut wrong_receipt_digest = digest;
	wrong_receipt_digest[0] ^= 1;
	for (committed, receipt_digest) in [
		(
			RemoteReplayBoundary {
				head: wrong_head,
				..boundary
			},
			digest,
		),
		(
			RemoteReplayBoundary {
				offset: boundary.offset + 1,
				..boundary
			},
			digest,
		),
		(boundary, wrong_receipt_digest),
	] {
		assert!(matches!(
			selected_terminal_history(replay, native_end, committed, receipt_digest),
			Err(WitnessedInspectionError::SelectionMismatch)
		));
	}
}

fn check_first_pass(
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) {
	let ordinary = hex(vector!("remote_finalization/retirement_journal.hex"));
	let mut frames = FrameReader::new(ordinary.as_slice(), ChainHead::start());
	let (retirement_start, retirement_end) = loop {
		let start = frames.offset() as usize;
		let frame = frames.next_frame().unwrap().unwrap();
		if frame.kind() == FrameKind::RemoteCaptureRetired {
			break (start, frames.offset() as usize);
		}
	};
	for (bytes, retired) in [
		(&ordinary[..retirement_start], false),
		(&ordinary[..retirement_end], true),
		(ordinary.as_slice(), true),
	] {
		let replay = replay_remote_witnessed_closeout(bytes, trust, selection).unwrap();
		assert!(replay.issue().is_none());
		assert_eq!(replay.boundary().offset, bytes.len() as u64);
		assert_eq!(replay.has_ordinary_retirements(), retired);
		assert!(!first_unretired_witnessed_pass(&replay));
	}

	let vector = vector!("remote_continuation/witnessed_replay.hex");
	for (label, witnessed_passes, witnessed_retired) in [
		("published", 1, false),
		("retire-preserved", 1, true),
		("repeated-v2", 2, false),
		("fresh-v1-then-v2", 2, true),
	] {
		let bytes = field(vector, label);
		let replay = replay_remote_witnessed_closeout(bytes.as_slice(), trust, selection).unwrap();
		assert!(replay.issue().is_none());
		assert_eq!(replay.boundary().offset, bytes.len() as u64);
		assert!(!replay.has_ordinary_retirements());
		assert_eq!(
			replay.pass_count() - replay.attempts().len(),
			witnessed_passes,
		);
		assert_eq!(!replay.retirements().is_empty(), witnessed_retired);
		assert_eq!(
			first_unretired_witnessed_pass(&replay),
			label == "published",
		);
	}
}

fn check_receipt_ready(
	bytes: &[u8],
	receipt_bytes: &[u8],
	other_receipt_bytes: &[u8],
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) -> RemoteReplayBoundary {
	let mut frames = FrameReader::new(bytes, ChainHead::start());
	let (durable, ready) = loop {
		let frame = frames.next_frame().unwrap().unwrap();
		if frame.kind() == FrameKind::DurabilityRecorded {
			let durable = RemoteReplayBoundary {
				head: frame.head(),
				offset: frames.offset(),
			};
			let frame = frames.next_frame().unwrap().unwrap();
			assert_eq!(frame.kind(), FrameKind::RemoteReceiptReady);
			break (
				durable,
				RemoteReplayBoundary {
					head: frame.head(),
					offset: frames.offset(),
				},
			);
		}
	};
	let ready_end = usize::try_from(ready.offset).unwrap();
	let replay = replay_remote_witnessed_closeout(&bytes[..ready_end], trust, selection).unwrap();
	let inspection = receipt_ready_history(&replay, ready.offset).unwrap();
	assert_eq!(inspection.boundary(), ready);
	assert_eq!(inspection.durability_boundary(), durable);
	assert_eq!(inspection.bytes(), receipt_bytes);

	let receipt = LinuxFileIdentity::new(7, 14);
	assert_eq!(inspection.record().receipt(), receipt);
	verify_receipt_ready_bytes(&inspection, receipt, receipt_bytes).unwrap();
	for identity in [LinuxFileIdentity::new(7, 18), LinuxFileIdentity::new(8, 14)] {
		assert!(matches!(
			verify_receipt_ready_bytes(&inspection, identity, receipt_bytes),
			Err(WitnessedInspectionError::ReceiptMismatch)
		));
	}
	let mut extended = receipt_bytes.to_vec();
	extended.push(0);
	let mut changed = receipt_bytes.to_vec();
	changed[0] ^= 1;
	for bytes in [
		&receipt_bytes[..receipt_bytes.len() - 1],
		extended.as_slice(),
		changed.as_slice(),
		other_receipt_bytes,
	] {
		assert!(matches!(
			verify_receipt_ready_bytes(&inspection, receipt, bytes),
			Err(WitnessedInspectionError::ReceiptMismatch)
		));
	}

	for native_end in [ready.offset - 1, ready.offset + 1] {
		assert!(matches!(
			receipt_ready_history(&replay, native_end),
			Err(WitnessedInspectionError::History {
				phase: Phase::ReceiptReadyRequiresInspection,
				boundary,
				issue: None,
			}) if boundary == ready
		));
	}
	let torn = replay_remote_witnessed_closeout(&bytes[..ready_end + 1], trust, selection).unwrap();
	assert!(matches!(
		receipt_ready_history(&torn, ready.offset),
		Err(WitnessedInspectionError::History {
			phase: Phase::ReceiptReadyRequiresInspection,
			boundary,
			issue: Some(ReplayIssue::Torn),
		}) if boundary == ready
	));

	let durable_end = usize::try_from(durable.offset).unwrap();
	for (cut, phase) in [
		(&bytes[..durable_end], Phase::Durable),
		(bytes, Phase::ReceiptCommitted),
	] {
		let replay = replay_remote_witnessed_closeout(cut, trust, selection).unwrap();
		assert!(matches!(
			receipt_ready_history(&replay, u64::try_from(cut.len()).unwrap()),
			Err(WitnessedInspectionError::History {
				phase: observed,
				issue: None,
				..
			}) if observed == phase
		));
	}
	ready
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
