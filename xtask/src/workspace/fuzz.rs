use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use toml::{Table, Value};

use super::{LOCKFILE_NAME, MANIFEST_NAME};

pub(super) fn owns_manifest_or_lock(root: &Path, path: &Path, members: &BTreeSet<&Path>) -> bool {
	if !path.starts_with(root.join("crates"))
		|| !matches!(
			path.file_name().and_then(|name| name.to_str()),
			Some(MANIFEST_NAME | LOCKFILE_NAME)
		) {
		return false;
	}
	let Some(directory) = path
		.parent()
		.filter(|parent| parent.file_name().is_some_and(|name| name == "fuzz"))
	else {
		return false;
	};
	let Some(owner) = directory
		.parent()
		.filter(|parent| members.contains(parent.join(MANIFEST_NAME).as_path()))
	else {
		return false;
	};
	let Some(name) = owner.file_name().and_then(|name| name.to_str()) else {
		return false;
	};
	let manifest = directory.join(MANIFEST_NAME);
	if directory.is_symlink() || manifest.is_symlink() {
		return false;
	}
	let Ok(source) = fs::read_to_string(manifest) else {
		return false;
	};
	let Ok(table) = toml::from_str::<Table>(&source) else {
		return false;
	};
	table.get("package").is_some_and(|package| {
		package.get("name").and_then(Value::as_str) == Some(&format!("{name}-fuzz"))
			&& package.get("publish").and_then(Value::as_bool) == Some(false)
			&& package
				.get("metadata")
				.and_then(|metadata| metadata.get("cargo-fuzz"))
				.and_then(Value::as_bool)
				== Some(true)
	}) && table
		.get("workspace")
		.and_then(|workspace| workspace.get("resolver"))
		.and_then(Value::as_str)
		== Some("3")
}

#[cfg(test)]
mod tests {
	use std::collections::BTreeSet;

	use super::owns_manifest_or_lock;
	use crate::test_support::Fixture;

	#[test]
	fn admits_only_the_owned_private_fuzz_manifest_and_its_direct_lock() {
		const OWNER: &str = "crates/formats/exacopy-plan";
		const VALID: &str = r#"
[package]
name = "exacopy-plan-fuzz"
publish = false

[package.metadata]
cargo-fuzz = true

[workspace]
resolver = "3"
"#;
		let fixture = Fixture::new();
		let manifest = fixture.root().join(OWNER).join("Cargo.toml");
		let members = BTreeSet::from([manifest.as_path()]);
		fixture.write(&format!("{OWNER}/fuzz/Cargo.toml"), VALID);

		for (relative, allowed) in [
			("fuzz/Cargo.toml", true),
			("fuzz/Cargo.lock", true),
			("fuzz/rustfmt.toml", false),
			("fuzz/hidden/Cargo.toml", false),
			("fuzz/hidden/Cargo.lock", false),
			("src/fuzz/Cargo.toml", false),
		] {
			assert_eq!(
				owns_manifest_or_lock(
					fixture.root(),
					&fixture.root().join(OWNER).join(relative),
					&members
				),
				allowed,
				"{relative}"
			);
		}

		for invalid in [
			VALID.replace("publish = false", "publish = true"),
			VALID.replace("cargo-fuzz = true", "cargo-fuzz = false"),
			VALID.replace("exacopy-plan-fuzz", "exacopy-other-fuzz"),
		] {
			fixture.write(&format!("{OWNER}/fuzz/Cargo.toml"), &invalid);
			assert!(!owns_manifest_or_lock(
				fixture.root(),
				&fixture.root().join(OWNER).join("fuzz/Cargo.toml"),
				&members
			));
		}
	}
}
