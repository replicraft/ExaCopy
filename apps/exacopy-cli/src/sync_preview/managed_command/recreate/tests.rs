use super::*;

#[test]
fn prepare_recreate_refuses_oversize_receipt_without_candidate() {
	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	let mut input = &[0; MANAGED_ACK_BYTES + 1][..];
	assert_eq!(
		run(
			&ManagedSyncRecreateArgs {
				profile: "/absent-fixture-profile".into(),
				owner_key: [0x12; 32],
				selection: [0x31; 16],
				from: SyncSide::Left,
				reviewed: SyncConflict::DeletionAgainstUnchanged {
					absent: SyncSide::Right,
				},
				expires_in_seconds: None,
			},
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

#[test]
fn plan_expiry_preserves_fraction_and_refuses_seconds_overflow() {
	let duration = NonZeroU32::new(u32::MAX);
	let created = UnixTimestamp::new(i64::MAX - i64::from(u32::MAX), 987_654_321).unwrap();
	assert_eq!(plan_expiry(created, None), Ok(None));
	assert_eq!(
		plan_expiry(created, duration),
		Ok(Some(UnixTimestamp::new(i64::MAX, 987_654_321).unwrap()))
	);
	assert_eq!(
		plan_expiry(
			UnixTimestamp::new(created.seconds() + 1, 0).unwrap(),
			duration
		),
		Err("child_plan_expiry_overflow")
	);
}
