use super::super::{Case, selector};
use super::{CaseKind, Fixture, MANIFEST, OWNER, Path, Profile, matches_case, matches_fixture};

const FIXTURE: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/../apps/exacopy-cli/verification/public_stage_ext4/fixture.toml",
));

fn resolved() -> Fixture {
	toml::from_str(FIXTURE).unwrap()
}

#[test]
fn public_stage_accepts_only_its_canonical_owner_and_path() {
	let mut fixture = resolved();
	let manifest = Path::new(MANIFEST);
	assert!(matches_fixture(OWNER, manifest, &fixture));
	assert!(!matches_fixture("exacopy-platform", manifest, &fixture));
	for invalid in [
		"verification/other/fixture.toml",
		"verification/public_stage_ext4/./fixture.toml",
		"verification/public_stage_ext4//fixture.toml",
	] {
		assert!(!matches_fixture(OWNER, Path::new(invalid), &fixture));
	}
	fixture.profile = Profile::UnprivilegedSameDeviceBind;
	assert!(!matches_fixture(OWNER, manifest, &fixture));
	assert!(matches_fixture(
		"exacopy-platform",
		Path::new("verification/other/fixture.toml"),
		&fixture,
	));
}

#[test]
fn public_stage_rejects_case_and_custody_substitution() {
	let manifest = Path::new(MANIFEST);
	let changes: [fn(&mut Fixture); 14] = [
		|fixture: &mut Fixture| fixture.cases.clear(),
		|fixture: &mut Fixture| fixture.cases.extend(resolved().cases),
		|fixture: &mut Fixture| fixture.cases[0].kind = CaseKind::Command,
		|fixture: &mut Fixture| fixture.cases[0].kind = CaseKind::RustIntegration,
		|fixture: &mut Fixture| fixture.cases[0].ignored = false,
		|fixture: &mut Fixture| fixture.cases[0].owner = Some("exacopy-cli".into()),
		|fixture: &mut Fixture| fixture.cases[0].test_target = Some("foreign".into()),
		|fixture: &mut Fixture| fixture.cases[0].required_feature = Some("foreign".into()),
		|fixture: &mut Fixture| fixture.cases[0].source = "src/other.rs".into(),
		|fixture: &mut Fixture| fixture.cases[0].selector = "other".into(),
		|fixture: &mut Fixture| fixture.id = "other".into(),
		|fixture: &mut Fixture| fixture.runner = "verification/other/run.py".into(),
		|fixture: &mut Fixture| fixture.controls = "verification/other/test_runner.py".into(),
		|fixture: &mut Fixture| fixture.workflow = ".github/workflows/other.yml".into(),
	];
	for change in changes {
		let mut fixture = resolved();
		change(&mut fixture);
		assert!(!matches_fixture(OWNER, manifest, &fixture));
	}
}

#[test]
fn public_stage_selector_exception_preserves_existing_platform_path_rules() {
	let mut fixture = resolved();
	let case = &mut fixture.cases[0];
	let parse = |owner: &str, profile, case: &Case| {
		selector(
			&case.source,
			&case.selector,
			matches_case(owner, profile, case),
		)
	};
	let profile = fixture.profile;
	let (modules, _) = parse(OWNER, profile, case).unwrap();
	assert_eq!(modules, ["assembly", "linux", "public_stage", "tests"]);
	assert!(parse("exacopy-platform", profile, case).is_none());
	assert!(parse(OWNER, Profile::UnprivilegedSameDeviceBind, case).is_none());
	case.selector = "assembly::linux::public_stage::tests::different_test".into();
	assert!(parse(OWNER, profile, case).is_none());
	case.source = "src/assembly/linux/other.rs".into();
	case.selector = "assembly::linux::other::different_test".into();
	assert!(parse(OWNER, profile, case).is_none());
	assert!(
		selector(
			Path::new("src/linux/platform_only.rs"),
			"linux::platform_only::case",
			false,
		)
		.is_some()
	);
}
