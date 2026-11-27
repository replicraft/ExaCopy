use ed25519_dalek::SigningKey;
use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;

use crate::assembly::linux::ArchivedWitnessedSelection;

use super::*;

// Report/decoder integration only: these synthetic selectors confer no authority.
pub(super) fn summary() -> WitnessedSummary {
	let committed = RemoteReplayBoundary {
		head: ChainHead::after(18, [9; 32]).unwrap(),
		offset: 4096,
	};
	WitnessedSummary {
		archive_selection: ArchivedWitnessedSelection {
			job: job().id,
			owner_key: SigningKey::from_bytes(&[4; 32]).verifying_key(),
			route: RemoteQualificationRouteClass::DirectPinnedTcpV1,
			path_root: SftpPathRoot::AccountRelative,
			scope: RemoteScopeDigest::from_bytes([3; 32]),
			op1_digest: [5; 32],
			op2_digest: [8; 32],
			base_grant_digest: [2; 32],
			committed,
			receipt_digest: [7; 32],
		},
		committed,
		length: 64,
		receipt_digest: [7; 32],
		canonical_receipt_length: 1024,
		qualification: [8; 32],
		witness_links: 2,
		metadata_omissions: SftpDataOnlyV1::omissions(),
	}
}

#[test]
fn producer_report_roundtrips_the_independently_selected_archive() {
	let outcome = RemoteOutcome::published_with_witness(job(), summary());
	let bytes = serde_json::to_vec(&outcome.report()).unwrap();
	let decoded = crate::witness_archive::decode(&bytes).unwrap();
	assert_eq!(decoded.selection.job, job().id);
	assert_eq!(
		decoded.selection.scope,
		RemoteScopeDigest::from_bytes([3; 32])
	);
	assert_eq!(decoded.selection.base_grant_digest, [2; 32]);
	assert_eq!(decoded.selection.op1_digest, [5; 32]);
	assert_eq!(decoded.selection.op2_digest, [8; 32]);
	assert_eq!(decoded.selection.committed, summary().committed);
	assert_eq!(decoded.selection.receipt_digest, [7; 32]);
	assert_eq!(decoded.receipt_length, 1024);
	assert_eq!(decoded.stream_length, 64);
}

#[test]
fn inconsistent_archive_cannot_be_reported_as_committed_success() {
	for mismatch in 0..4 {
		let mut selected = summary();
		match mismatch {
			0 => {
				let mut other = *job().id.as_bytes();
				other[15] ^= 1;
				selected.archive_selection.job = JournalJobId::from_bytes(other).unwrap();
			}
			1 => selected.archive_selection.committed.offset += 1,
			2 => selected.archive_selection.receipt_digest = [1; 32],
			_ => selected.archive_selection.op2_digest = [1; 32],
		}
		let outcome = RemoteOutcome::published_with_witness(job(), selected);
		let json = serde_json::to_value(outcome.report()).unwrap();
		assert_eq!(outcome.exit_code(), 9);
		assert_eq!(json["publication"], "published");
		assert_eq!(json["error"]["code"], "E_RECOVERY_REQUIRED");
		assert!(json.get("receipt").is_none());
	}
}
