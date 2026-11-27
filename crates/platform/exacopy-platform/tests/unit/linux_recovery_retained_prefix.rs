use std::fs;

use super::{Fixture, PREFIX, StageError, inventory, selection};

#[test]
fn retained_prefix_refuses_a_missing_stage_without_consuming_its_access() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let original = inventory(&lease);
	let expected = selection(&original);
	let parked = fixture.scratch.path("parked-prefix");
	fs::rename(fixture.stage(), &parked).unwrap();

	let missing = inventory(&lease);
	assert!(missing.stage().is_none());
	assert!(matches!(
		lease.read_retained_prefix(&missing, expected),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(&parked).unwrap(), PREFIX);
	assert!(!fixture.stage().exists());
	assert!(!fixture.target().exists());

	fs::rename(&parked, fixture.stage()).unwrap();
	let restored = inventory(&lease);
	assert!(lease.read_retained_prefix(&restored, expected).is_ok());
}
