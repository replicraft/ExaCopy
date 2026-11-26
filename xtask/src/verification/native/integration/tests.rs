use super::{CargoTargets, exact_features, has_linux_test, valid_declaration};
use crate::verification::native::STATMOUNT_FEATURE;
use std::path::Path;

const NAME: &str = "selected";
const SOURCE: &str = "tests/selected.rs";

fn source(cfg: &str, test_attributes: &str) -> String {
	format!(
		r#"
#![{cfg}]
#[test]
#[ignore = "requires native whole ext4"]
{test_attributes}
fn {NAME}() {{
	assert!(observation().is_ok());
}}
"#
	)
}

#[test]
fn requires_closed_linux_and_exact_feature_conjunction() {
	let production = format!(r#"cfg(all(target_os = "linux", feature = "{STATMOUNT_FEATURE}"))"#);
	let feature = Some(STATMOUNT_FEATURE);
	assert!(has_linux_test(&source(&production, ""), NAME, feature));
	assert!(!has_linux_test(&source(&production, ""), NAME, None));

	let ordinary = r#"cfg(target_os = "linux")"#;
	assert!(has_linux_test(&source(ordinary, ""), NAME, None));
	assert!(!has_linux_test(&source(ordinary, ""), NAME, feature));

	for cfg in [
		production.replace("all(", "any("),
		production.replace(STATMOUNT_FEATURE, "replacement-feature"),
		production.replace("linux", "macos"),
		production.replace("))", ", test))"),
		format!("{production}]\n#![cfg_attr(test, no_main)"),
	] {
		assert!(!has_linux_test(&source(&cfg, ""), NAME, feature));
	}
	assert!(!has_linux_test(
		&source(&production, r#"#[cfg(not(test))]"#),
		NAME,
		feature
	));
}

#[test]
fn compares_the_exact_feature_inventory() {
	let declared = STATMOUNT_FEATURE.to_owned();
	assert!(exact_features(&[], None));
	assert!(exact_features(
		std::slice::from_ref(&declared),
		Some(STATMOUNT_FEATURE)
	));
	assert!(!exact_features(std::slice::from_ref(&declared), None));
	assert!(!exact_features(&[], Some(STATMOUNT_FEATURE)));
	assert!(!exact_features(
		&[declared.clone(), declared.clone()],
		Some(STATMOUNT_FEATURE)
	));
	assert!(!exact_features(
		&[declared, "spoof".into()],
		Some(STATMOUNT_FEATURE)
	));
}

#[test]
fn feature_requires_an_explicit_canonical_libtest_target() {
	let path = Path::new(SOURCE);
	let feature = Some(STATMOUNT_FEATURE);
	assert!(valid_declaration(None, NAME, path, None));
	assert!(!valid_declaration(None, NAME, path, feature));
	let exact = format!(
		r#"[[test]]
name = "{NAME}"
path = "{SOURCE}"
required-features = ["{STATMOUNT_FEATURE}"]
"#
	);
	let valid = |text: &str| {
		let parsed: CargoTargets = toml::from_str(text).unwrap();
		valid_declaration(parsed.tests.first(), NAME, path, feature)
	};
	assert!(valid(&exact));
	for candidate in [
		exact.replace("name = \"selected\"\n", ""),
		exact.replace(&format!("path = \"{SOURCE}\"\n"), ""),
		exact.replace(SOURCE, "tests/./selected.rs"),
		exact.replace(STATMOUNT_FEATURE, "other"),
		format!("{exact}harness = false\n"),
	] {
		assert!(!valid(&candidate));
	}
}
