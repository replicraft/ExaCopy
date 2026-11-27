use super::{CaseKind, Fixture, OWNER, Path, Profile, WITNESSED, witnessed};

const FIXTURE: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/../crates/platform/exacopy-platform/verification/witnessed_components_ext4/fixture.toml",
));

#[test]
fn witnessed_fixture_is_closed_to_the_owned_component_inventory() {
	let manifest = Path::new(WITNESSED);
	let mut fixture: Fixture = toml::from_str(FIXTURE).unwrap();
	assert!(witnessed(OWNER, manifest, &fixture));
	assert!(!witnessed("exacopy-cli", manifest, &fixture));
	assert!(!witnessed(
		OWNER,
		Path::new("verification/other/fixture.toml"),
		&fixture
	));
	fixture.cases.swap(0, 1);
	assert!(!witnessed(OWNER, manifest, &fixture));
	fixture.cases.swap(0, 1);
	fixture.cases[0].kind = CaseKind::Command;
	assert!(!witnessed(OWNER, manifest, &fixture));
	fixture.cases[0].kind = CaseKind::RustUnit;
	fixture.cases[0].ignored = false;
	assert!(!witnessed(OWNER, manifest, &fixture));
	fixture.cases[0].ignored = true;
	fixture.profile = Profile::UnprivilegedSameDeviceBind;
	assert!(!witnessed(OWNER, manifest, &fixture));
}
