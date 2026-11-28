use std::path::Path;

use super::{
	FEATURE, MANIFEST, OWNER, PREPARED_FEATURE, SELECTOR, SOURCE, TARGET, matches_fixture,
	matches_prepared_component,
};
use crate::verification::native::{Case, CaseKind, Profile};

const PRODUCTION: Profile = Profile::UnprivilegedWholeExt4ManagedSyncProduction;

#[test]
fn prepared_component_bound_only_to_managed_production_and_public_apply() {
	assert!(matches_prepared_component(
		PRODUCTION,
		Some(PREPARED_FEATURE)
	));
	assert!(!matches_prepared_component(PRODUCTION, None));
	assert!(!matches_prepared_component(PRODUCTION, Some(FEATURE)));
	for other in [
		Profile::UnprivilegedWholeExt4ManagedSyncGenesisProduction,
		Profile::UnprivilegedWholeExt4SyncStatmount,
		Profile::WindowsFixedNtfsPublication,
	] {
		assert!(matches_prepared_component(other, None));
		assert!(!matches_prepared_component(other, Some(PREPARED_FEATURE)));
	}
}

fn exact_case() -> Case {
	toml::from_str(&format!(
		r#"
kind = "rust-integration"
selector = "{SELECTOR}"
source = "{SOURCE}"
test_target = "{TARGET}"
required_feature = "{FEATURE}"
ignored = true
"#,
	))
	.unwrap()
}

#[test]
fn requires_exact_owner_profile_and_manifest_spelling() {
	let cases = [exact_case()];
	let manifest = Path::new(MANIFEST);
	assert!(matches_fixture(OWNER, manifest, PRODUCTION, &cases));
	assert!(!matches_fixture(
		"exacopy-platform",
		manifest,
		PRODUCTION,
		&cases
	));
	for path in [
		"verification/managed_sync_production/./fixture.toml",
		"verification/managed_sync_production//fixture.toml",
		"verification/elsewhere/fixture.toml",
	] {
		assert!(
			!matches_fixture(OWNER, Path::new(path), PRODUCTION, &cases),
			"{path}"
		);
	}
	for profile in [
		Profile::UnprivilegedWholeExt4SyncHistory,
		Profile::UnprivilegedWholeExt4SyncStatmount,
	] {
		assert!(!matches_fixture(OWNER, manifest, profile, &cases));
		assert!(matches_fixture(
			"exacopy-platform",
			Path::new("verification/platform_fixture/fixture.toml"),
			profile,
			&cases,
		));
	}
}

#[test]
fn refuses_individually_substituted_case_fields_and_additional_cases() {
	let accepts = |cases: &[Case]| matches_fixture(OWNER, Path::new(MANIFEST), PRODUCTION, cases);
	assert!(accepts(&[exact_case()]));
	assert!(!accepts(&[]));
	assert!(!accepts(&[exact_case(), exact_case()]));
	let replacements: [fn(&mut Case); 9] = [
		|case| case.selector.push_str("_alternate"),
		|case| case.source = "tests/./linux_managed_sync_production.rs".into(),
		|case| case.source = "tests/alternate.rs".into(),
		|case| case.test_target = Some("alternate".into()),
		|case| case.required_feature = None,
		|case| case.required_feature = Some("different-feature".into()),
		|case| case.ignored = false,
		|case| case.kind = CaseKind::Command,
		|case| case.owner = Some(OWNER.into()),
	];
	for replace in replacements {
		let mut case = exact_case();
		replace(&mut case);
		assert!(!accepts(&[case]));
	}
}
