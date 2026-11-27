use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;

use super::*;

#[test]
fn clean_live_and_recovered_archives_project_exact_terminal_inspection() {
	let run = Transcript::read(false);
	let destination = &run.fixture.owner.manifest().scope.destination;
	for (label, receipt_label, stale_receipt_label) in [
		("published", "receipt", "recovered-receipt"),
		("recovered-published", "recovered-receipt", "receipt"),
	] {
		let bytes = recorded(label);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		let checked = replay.committed_receipt_inspection().unwrap();
		assert_eq!(
			checked.boundary(),
			boundary_of(&bytes, FrameKind::ReceiptCommitted)
		);
		assert_eq!(
			checked.record().boundary(),
			boundary_of(&bytes, FrameKind::RemoteReceiptReady)
		);
		assert_eq!(checked.record().receipt(), LinuxFileIdentity::new(7, 14));
		assert_eq!(
			checked.witness().boundary(),
			boundary_of(&bytes, FrameKind::RemoteWitnessIntent)
		);
		assert_eq!(
			checked.witness().job_directory(),
			LinuxFileIdentity::new(7, 11)
		);
		assert_eq!(checked.destination(), destination);
		assert_eq!(
			checked.allocation(),
			boundary_of(&bytes, FrameKind::RemoteStageAllocated).head
		);
		assert_eq!(
			checked.stage().head,
			boundary_of(&bytes, FrameKind::EntryPrepared).head
		);
		assert_eq!(checked.stage().directory, LinuxFileIdentity::new(7, 12));
		assert_eq!(checked.stage().file, LinuxFileIdentity::new(7, 13));
		assert_eq!(checked.stage().file, checked.witness().binding().stage());
		assert_eq!(checked.stage_name(), STAGE_NAME);
		assert_eq!(checked.extent(), length(4));
		assert_eq!(
			checked.stage_digest(),
			StreamDigest::from_bytes(*blake3::hash(b"ABCD").as_bytes()),
		);
		assert_eq!(
			checked.metadata(),
			RemoteLocalMetadata {
				uid: 1001,
				gid: 1002
			}
		);
		assert_eq!(checked.mode(), 0o600);
		assert_eq!(
			checked.outcome(),
			if label == "published" {
				RemoteWitnessedOutcome::Submitted(checked.stage().file)
			} else {
				RemoteWitnessedOutcome::Recovered {
					target: checked.stage().file,
					witness: checked.witness().boundary().head,
				}
			},
		);

		let ready_offset = usize::try_from(checked.record().boundary().offset).unwrap();
		let at_ready = scan(&run, &bytes[..ready_offset], FRESH);
		let prior = at_ready.receipt_ready_inspection().unwrap();
		assert_eq!(checked.pending_name(), prior.pending_name());
		assert_eq!(checked.final_name(), prior.final_name());
		assert!(
			replay.matches_committed_receipt(checked.record().receipt(), &recorded(receipt_label))
		);
		assert!(
			!replay.matches_committed_receipt(
				checked.record().receipt(),
				&recorded(stale_receipt_label)
			)
		);
	}
}

#[test]
fn committed_inspection_refuses_stale_phase_wrong_binding_and_any_tail() {
	let run = Transcript::read(false);
	for label in [
		"archived-expired-consent",
		"conflict",
		"uncertain",
		"retire-preserved",
		"wrong-ready-digest",
		"wrong-committed-inode",
	] {
		let bytes = recorded(label);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		assert!(replay.committed_receipt_inspection().is_err(), "{label}");
	}

	let mut bytes = recorded("published");
	let end = bytes.len();
	let ready = boundary_of(&bytes, FrameKind::RemoteReceiptReady);
	let ready_offset = usize::try_from(ready.offset).unwrap();
	for cut in [ready_offset, ready_offset + 1, end - 1] {
		let replay = scan(&run, &bytes[..cut], FRESH);
		assert_eq!(replay.boundary(), ready);
		assert!(
			replay.committed_receipt_inspection().is_err(),
			"short archive at {cut}"
		);
	}

	let replay_tail = bytes[ready_offset..].to_vec();
	bytes.push(0);
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_eq!(replay.phase(), Phase::ReceiptCommitted);
	assert!(replay.issue().is_some());
	assert!(replay.committed_receipt_inspection().is_err());
	bytes.truncate(end);
	bytes.extend_from_slice(&replay_tail);
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_eq!(replay.phase(), Phase::ReceiptCommitted);
	assert!(replay.issue().is_some());
	assert!(replay.committed_receipt_inspection().is_err());
}

#[test]
fn exact_kind7_projects_original_public_expectation_without_a_recovered_outcome() {
	let run = Transcript::read(false);
	let bytes = recorded("published");
	let cut = boundary_of(&bytes, FrameKind::PublishIntent);
	let offset = usize::try_from(cut.offset).unwrap();
	let exact = scan(&run, &bytes[..offset], FRESH);
	let intent = exact.publish_intent_inspection().unwrap();
	assert_eq!(intent.boundary(), cut);
	assert_eq!(intent.stage_name(), STAGE_NAME);
	assert_eq!(intent.stage().file, LinuxFileIdentity::new(7, 13));
	assert_eq!(
		intent.stage_digest(),
		StreamDigest::from_bytes(*blake3::hash(b"ABCD").as_bytes())
	);
	assert_eq!(
		intent.destination(),
		&run.fixture.owner.manifest().scope.destination
	);
	assert!(exact.observed_outcome().is_none());
	assert!(exact.committed_receipt_inspection().is_err());

	let terminal = scan(&run, bytes.as_slice(), FRESH);
	let committed = terminal.committed_receipt_inspection().unwrap();
	assert_eq!(intent.stage_digest(), committed.stage_digest());
	assert_eq!(intent.metadata(), committed.metadata());
	assert!(terminal.publish_intent_inspection().is_err());

	let mut tailed = bytes[..offset].to_vec();
	tailed.push(0);
	for refused in [&bytes[..offset - 1], tailed.as_slice()] {
		assert!(
			scan(&run, refused, FRESH)
				.publish_intent_inspection()
				.is_err()
		);
	}
}
