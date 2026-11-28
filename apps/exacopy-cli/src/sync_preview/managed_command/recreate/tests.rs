use super::*;

#[test]
fn prepare_recreate_refuses_oversize_receipt_without_candidate() {
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	let mut input = &[0; MANAGED_ACK_BYTES + 1][..];
	assert_eq!(
		run(
			Path::new("/absent-fixture-profile"),
			[0x12; 32],
			[0x31; 16],
			(
				SyncSide::Left,
				SyncConflict::DeletionAgainstUnchanged {
					absent: SyncSide::Right
				}
			),
			&mut input,
			&mut stdout,
			&mut stderr,
		),
		INCONCLUSIVE,
	);
	assert!(stderr.is_empty());
	let observed: Value = serde_json::from_slice(&stdout).unwrap();
	assert_eq!(
		observed,
		json!({
			"schema": "exacopy.cli.managed_sync_recreate_plan",
			"schema_version": "1.0",
			"result": "refused",
			"authority": "none",
			"approval_required": true,
			"copy_started": false,
			"baseline_advanced": false,
			"reason": "input_limit",
		})
	);
}
