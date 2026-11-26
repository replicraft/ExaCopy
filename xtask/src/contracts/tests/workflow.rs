use super::{Contract, Fixture, check_record};

const OWNER: &str = "crates/formats/exacopy-plan/src/workflow_sync/wire.rs";
const SOURCE: &str = r#"const VERSION: [u64; 2] = [1, 0];
const ROOT_REQUIRED_FEATURES: u64 = 69;
const ENDPOINT_REQUIRED_FEATURES: u64 = 1;
"#;

#[test]
fn workflow_profiles_require_their_own_feature_mask_and_private_kind() {
	let fixture = Fixture::new();
	for (id, mask, feature) in [
		(
			"workflow-local-sync-endpoint",
			1,
			"ENDPOINT_REQUIRED_FEATURES",
		),
		("workflow-sync-genesis-root", 69, "ROOT_REQUIRED_FEATURES"),
	] {
		let text = format!(
			r#"id = {id:?}
kind = "workflow_record"
status = "implemented_private"
version = "1.0"
required_features = {mask}
owner = {OWNER:?}
"#
		);
		let record: Contract = toml::from_str(&text).unwrap();
		fixture.write(OWNER, SOURCE);
		assert_eq!(check_record(fixture.root(), &record), Ok(()));
		for source in [
			SOURCE.replace("[1, 0]", "[2, 0]"),
			SOURCE.replace(
				&format!("{feature}: u64 = {mask}"),
				&format!("{feature}: u64 = 0"),
			),
		] {
			fixture.write(OWNER, &source);
			assert!(check_record(fixture.root(), &record).is_err());
		}
		fixture.write(OWNER, SOURCE);
		for changed in [
			text.replace("workflow_record", "transfer_journal"),
			text.replace("implemented_private", "implemented"),
		] {
			let wrong: Contract = toml::from_str(&changed).unwrap();
			assert!(check_record(fixture.root(), &wrong).is_err());
		}
	}
}
