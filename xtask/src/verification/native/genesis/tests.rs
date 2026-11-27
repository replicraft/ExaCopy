use std::path::Path;

use super::{
	CONTROLS, FEATURE, ID, MANIFEST, OWNER, RESULT, RUNNER, SELECTOR, SOURCE, TARGET, WORKFLOW,
	matches_fixture,
};
use crate::verification::native::{CaseKind, Fixture, Profile, Target};

const PREVIEW_MANIFEST: &str = "verification/managed_sync_production/fixture.toml";
const GENESIS: Profile = Profile::UnprivilegedWholeExt4ManagedSyncGenesisProduction;

fn fixture() -> Fixture {
	toml::from_str(&format!(
		r#"
schema_version = 1
id = "{ID}"
target = "x86_64-unknown-linux-gnu"
profile = "linux-unprivileged-whole-ext4-managed-sync-genesis-production-v1"
rust_toolchain = "1.100.0"
runner = "{RUNNER}"
controls = "{CONTROLS}"
workflow = "{WORKFLOW}"
result = "{RESULT}"

[[case]]
kind = "rust-integration"
test_target = "{TARGET}"
selector = "{SELECTOR}"
source = "{SOURCE}"
required_feature = "{FEATURE}"
ignored = true
"#,
	))
	.unwrap()
}

#[test]
fn requires_exact_new_app_fixture_and_preserves_existing_managed_preview() {
	let manifest = Path::new(MANIFEST);
	let mut resolved = fixture();
	assert!(matches_fixture(OWNER, manifest, &resolved));
	assert!(resolved.profile.integration());
	assert_eq!(resolved.profile.required_feature(), Some(FEATURE));
	assert!(resolved.profile.target() == Target::LinuxX86_64Gnu);
	assert!(!matches_fixture("exacopy-platform", manifest, &resolved));
	assert!(!matches_fixture(
		OWNER,
		Path::new(PREVIEW_MANIFEST),
		&resolved
	));
	for alias in [
		"verification/managed_sync_genesis_production/./fixture.toml",
		"verification/managed_sync_genesis_production//fixture.toml",
	] {
		assert!(
			!matches_fixture(OWNER, Path::new(alias), &resolved),
			"{alias}"
		);
	}

	resolved.profile = Profile::UnprivilegedWholeExt4ManagedSyncProduction;
	resolved.id = "linux-managed-sync-production".into();
	resolved.runner = "verification/managed_sync_production/run.py".into();
	resolved.controls = "verification/managed_sync_production/test_runner.py".into();
	resolved.workflow = ".github/workflows/linux-managed-sync-production-qualification.yml".into();
	let case = &mut resolved.cases[0];
	case.test_target = Some("linux_managed_sync_production".into());
	case.source = "tests/linux_managed_sync_production.rs".into();
	case.selector = "production_managed_init_then_preview_exact_p063_history".into();
	assert!(matches_fixture(
		OWNER,
		Path::new(PREVIEW_MANIFEST),
		&resolved
	));
	assert!(!matches_fixture(OWNER, manifest, &resolved));

	resolved.profile = GENESIS;
	assert!(!matches_fixture(OWNER, manifest, &resolved));
}

#[test]
fn refuses_custody_and_exact_case_substitution() {
	let manifest = Path::new(MANIFEST);
	let rejects = |change: fn(&mut Fixture)| {
		let mut resolved = fixture();
		change(&mut resolved);
		assert!(!matches_fixture(OWNER, manifest, &resolved));
	};
	let changes: [fn(&mut Fixture); 16] = [
		|fixture| fixture.id.push_str("-alternate"),
		|fixture| fixture.runner = "verification/managed_sync_genesis_production/./run.py".into(),
		|fixture| {
			fixture.controls = "verification/managed_sync_genesis_production/alternate.py".into()
		},
		|fixture| {
			fixture.workflow =
				".github/workflows/linux-managed-sync-production-qualification.yml".into()
		},
		|fixture| fixture.result = "./result.json".into(),
		|fixture| fixture.cases.clear(),
		|fixture| fixture.cases.append(&mut self::fixture().cases),
		|fixture| fixture.cases[0].kind = CaseKind::RustUnit,
		|fixture| fixture.cases[0].owner = Some(OWNER.into()),
		|fixture| fixture.cases[0].test_target = None,
		|fixture| fixture.cases[0].test_target = Some("linux_managed_sync_production".into()),
		|fixture| {
			fixture.cases[0].source = "tests/./linux_managed_sync_genesis_production.rs".into()
		},
		|fixture| fixture.cases[0].selector.push_str("_alternate"),
		|fixture| fixture.cases[0].required_feature = None,
		|fixture| fixture.cases[0].required_feature = Some("other-feature".into()),
		|fixture| fixture.cases[0].ignored = false,
	];
	for change in changes {
		rejects(change);
	}
}
