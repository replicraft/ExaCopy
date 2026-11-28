use exacopy_journal::DarwinReceiptDigest;

use super::*;

#[test]
fn apfs_inspection_keeps_reconciliation_separate_from_history_and_receipt() {
	use DarwinJournalTail::{Clean, Torn};
	use DarwinReceiptArtifact::{MatchesCommitment, Missing, PresentUncommitted};
	use DarwinReplayStatus::{Complete, Conflict, Incomplete, PublishedIncomplete, Uncertain};

	let matched = MatchesCommitment(DarwinReceiptDigest::from_bytes([0x5a; 32]));
	for (status, tail, receipt, exit) in [
		(Incomplete, Clean, Missing, 0),
		(Conflict, Clean, Missing, 0),
		(Complete, Clean, matched, 0),
		(Incomplete, Torn { bytes_read: 1 }, Missing, 9),
		(Complete, Torn { bytes_read: 1 }, matched, 9),
		(Complete, Clean, Missing, 9),
		(Complete, Clean, PresentUncommitted, 9),
		(PublishedIncomplete, Clean, Missing, 9),
		(Uncertain, Clean, Missing, 9),
		(Incomplete, Clean, PresentUncommitted, 9),
	] {
		assert_eq!(
			observation_exit_code(status, tail, receipt),
			exit,
			"{status:?}"
		);
	}
	let refused = Report::refused(Failure::Binding);
	assert_eq!(refused.exit_code(), 9);
	let json = serde_json::to_value(refused).unwrap();
	assert_eq!(
		json,
		serde_json::json!({
			"schema": "exacopy.cli.apfs_recovery_inspection",
			"schema_version": "1.0",
			"result": "refused",
			"code": "E_APFS_BINDING",
			"message": "the selected APFS job or held destination differs from the plan"
		})
	);
}
