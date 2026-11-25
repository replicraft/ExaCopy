use std::collections::{BTreeSet, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, Package, PackageId};
use toml::{Table, Value};

use crate::finding::Findings;

const APP_VERSION: &str = "1.100.0";
const APP_EDITION: &str = "2024";
const APP_LICENSE: &str = "Apache-2.0";
const MANIFEST_NAME: &str = "Cargo.toml";
const LOCKFILE_NAME: &str = "Cargo.lock";
const XTASK: &str = "xtask";
const DEPENDENCY_TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
const INHERITED_METADATA: [&str; 4] = ["version", "edition", "rust-version", "license"];
const RUST_INDENT_WIDTH: i64 = 4;
const RUST_MAX_WIDTH: i64 = 100;

pub(crate) fn metadata() -> Result<Metadata, cargo_metadata::Error> {
	MetadataCommand::new()
		.features(CargoOpt::AllFeatures)
		.other_options(vec!["--locked".into()])
		.exec()
}

pub(crate) fn check(metadata: &Metadata, files: &[std::path::PathBuf], findings: &mut Findings) {
	let root = metadata.workspace_root.as_std_path();
	let manifest = root.join(MANIFEST_NAME);
	check_workspace_manifest(&manifest, findings);
	check_format_config(root, findings);
	let member_manifests = metadata
		.workspace_packages()
		.into_iter()
		.map(|package| {
			check_package(root, package, findings);
			package.manifest_path.as_std_path()
		})
		.collect::<BTreeSet<_>>();
	for path in files {
		if path.starts_with(root.join("crates"))
			&& path
				.components()
				.any(|part| part.as_os_str() == OsStr::new("fuzz"))
		{
			continue;
		}
		match path.file_name().and_then(OsStr::to_str) {
			Some(MANIFEST_NAME)
				if path != &manifest && !member_manifests.contains(path.as_path()) =>
			{
				findings.add(
					path,
					"Cargo manifest is outside the application workspace membership",
				);
			}
			Some(LOCKFILE_NAME) if path != &root.join(LOCKFILE_NAME) => {
				findings.add(path, "use the root application Cargo.lock");
			}
			Some("rustfmt.toml" | ".rustfmt.toml") if path != &root.join("rustfmt.toml") => {
				findings.add(path, "use the root workspace rustfmt configuration");
			}
			_ => (),
		}
	}
	check_production_graph(metadata, findings);
}

fn check_workspace_manifest(path: &Path, findings: &mut Findings) {
	let Some((manifest, contents)) = read_manifest(path, findings) else {
		return;
	};
	let workspace = manifest.get("workspace").and_then(Value::as_table);
	if workspace
		.and_then(|table| table.get("resolver"))
		.and_then(Value::as_str)
		!= Some("3")
	{
		findings.add(path, "workspace must set resolver to 3");
	}
	let package = workspace
		.and_then(|table| table.get("package"))
		.and_then(Value::as_table);
	for (key, expected) in [
		("edition", APP_EDITION),
		("rust-version", APP_VERSION),
		("license", APP_LICENSE),
	] {
		if package
			.and_then(|table| table.get(key))
			.and_then(Value::as_str)
			!= Some(expected)
		{
			findings.add(
				path,
				format_args!("workspace.package.{key} must be {expected}"),
			);
		}
	}
	let lints = workspace
		.and_then(|table| table.get("lints"))
		.and_then(Value::as_table);
	let rust_lints = lints
		.and_then(|table| table.get("rust"))
		.and_then(Value::as_table);
	let unsafe_lint = rust_lints.and_then(|table| table.get("unsafe_op_in_unsafe_fn"));
	let level = unsafe_lint.and_then(|value| {
		value
			.as_str()
			.or_else(|| value.get("level").and_then(Value::as_str))
	});
	if !matches!(level, Some("deny" | "forbid")) {
		findings.add(path, "workspace must deny unsafe_op_in_unsafe_fn");
	}
	let dependencies = workspace
		.and_then(|table| table.get("dependencies"))
		.and_then(Value::as_table);
	if let Some(dependencies) = dependencies {
		check_dependency_groups(path, &contents, findings);
		for (name, dependency) in dependencies {
			let version = dependency
				.as_str()
				.or_else(|| dependency.get("version").and_then(Value::as_str));
			if version.is_some_and(|version| version.trim() == "*") {
				findings.add(path, format_args!("wildcard dependency {name}"));
			}
			if dependency.get("git").is_some() {
				let revision = dependency.get("rev").and_then(Value::as_str);
				if !revision.is_some_and(is_commit)
					|| dependency.get("branch").is_some()
					|| dependency.get("tag").is_some()
				{
					findings.add(
						path,
						format_args!("Git dependency {name} needs a full immutable revision"),
					);
				}
			}
		}
	}
}

fn check_dependency_groups(path: &Path, contents: &str, findings: &mut Findings) {
	let mut in_dependencies = false;
	let mut has_group = false;
	for (line, raw) in contents.lines().enumerate() {
		let text = raw.trim();
		if !raw.starts_with(char::is_whitespace) && text.starts_with('[') && text.ends_with(']') {
			if text.starts_with("[workspace.dependencies.") {
				findings.at_line(
					path,
					line + 1,
					"use a grouped declaration under [workspace.dependencies]",
				);
			}
			in_dependencies = text == "[workspace.dependencies]";
		} else if in_dependencies && let Some(comment) = text.strip_prefix('#') {
			has_group |= comment
				.split_whitespace()
				.any(|word| word.chars().any(char::is_alphabetic));
		} else if in_dependencies && !has_group && !text.is_empty() {
			findings.at_line(
				path,
				line + 1,
				"group workspace dependencies with descriptive TOML comments",
			);
			return;
		}
	}
}

fn check_package(root: &Path, package: &Package, findings: &mut Findings) {
	let path = package.manifest_path.as_std_path();
	let expected_location = if package.name.as_str() == XTASK {
		path == root.join(XTASK).join(MANIFEST_NAME)
	} else {
		package.name.starts_with("exacopy-")
			&& path
				.strip_prefix(root.join("crates"))
				.is_ok_and(|relative| relative.components().count() == 3)
	};
	if !expected_location {
		findings.add(
			path,
			"application members belong under crates/<group>/<crate> and use exacopy-* names",
		);
	}
	for target in &package.targets {
		let source = target.src_path.as_std_path();
		if !source.starts_with(root)
			|| source
				.canonicalize()
				.is_ok_and(|real| !real.starts_with(root))
		{
			findings.add(
				path,
				format_args!(
					"Cargo target source escapes the workspace: {}",
					source.display()
				),
			);
		}
		if matches!(package.name.as_str(), XTASK | "exacopy-model")
			&& matches!(
				source.file_name().and_then(OsStr::to_str),
				Some("lib.rs" | "main.rs")
			) {
			check_safe_crate(source, findings);
		}
	}
	let Some((manifest, _)) = read_manifest(path, findings) else {
		return;
	};
	if manifest.contains_key("workspace") || manifest.contains_key("profile") {
		findings.add(
			path,
			"workspace and build profiles belong in the root manifest",
		);
	}
	let metadata = manifest.get("package");
	for key in INHERITED_METADATA {
		if metadata
			.and_then(|table| table.get(key))
			.is_none_or(|entry| !inherited(entry))
		{
			findings.add(
				path,
				format_args!("package.{key} must inherit from the workspace"),
			);
		}
	}
	if manifest.get("lints").is_none_or(|entry| !inherited(entry)) {
		findings.add(path, "member must inherit workspace lints");
	}
	check_dependency_tables(path, &manifest, findings);
	if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
		for target in targets.values().filter_map(Value::as_table) {
			check_dependency_tables(path, target, findings);
		}
	}
}

fn check_safe_crate(path: &Path, findings: &mut Findings) {
	let source = fs::read_to_string(path)
		.ok()
		.and_then(|text| syn::parse_file(&text).ok());
	let forbidden = source.is_some_and(|file| {
		file.attrs.iter().any(|attr| {
			attr.path().is_ident("forbid")
				&& attr
					.parse_args_with(
						syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
					)
					.is_ok_and(|items| items.iter().any(|item| item.path().is_ident("unsafe_code")))
		})
	});
	if !forbidden {
		findings.add(path, "pure crates must explicitly forbid unsafe_code");
	}
}

fn check_dependency_tables(path: &Path, manifest: &Table, findings: &mut Findings) {
	for kind in DEPENDENCY_TABLES {
		if let Some(dependencies) = manifest.get(kind).and_then(Value::as_table) {
			for (name, entry) in dependencies {
				if !inherited(entry) {
					findings.add(
						path,
						format_args!("{kind}.{name} must inherit from the workspace"),
					);
				}
			}
		}
	}
}

fn inherited(entry: &Value) -> bool {
	entry.get("workspace").and_then(Value::as_bool) == Some(true)
}

fn check_production_graph(metadata: &Metadata, findings: &mut Findings) {
	let Some(graph) = &metadata.resolve else {
		findings.add(
			metadata.workspace_root.as_std_path(),
			"Cargo dependency resolution was unavailable",
		);
		return;
	};
	for package in metadata.workspace_packages() {
		let mut seen = HashSet::new();
		let mut pending = vec![&package.id];
		while let Some(id) = pending.pop() {
			if !seen.insert(id) {
				continue;
			}
			if id != &package.id
				&& let Some(dependency) = metadata.packages.iter().find(|entry| entry.id == *id)
				&& is_test_only(&dependency.name)
			{
				findings.add(
					package.manifest_path.as_std_path(),
					format_args!(
						"test-only dependency {} leaks into the production graph",
						dependency.name
					),
				);
			}
			pending.extend(production_dependencies(id, graph));
		}
	}
}

fn production_dependencies<'a>(
	id: &PackageId,
	graph: &'a cargo_metadata::Resolve,
) -> impl Iterator<Item = &'a PackageId> {
	graph
		.nodes
		.iter()
		.find(|node| node.id == *id)
		.into_iter()
		.flat_map(|node| &node.deps)
		.filter(|dependency| {
			dependency
				.dep_kinds
				.iter()
				.any(|kind| kind.kind != DependencyKind::Development)
		})
		.map(|dependency| &dependency.pkg)
}

fn is_test_only(name: &str) -> bool {
	matches!(
		name,
		"test-support"
			| "exacopy-test-support"
			| "proptest"
			| "proptest-state-machine"
			| "rstest"
			| "insta"
			| "mockall"
			| "wiremock"
			| "criterion"
			| "loom"
			| "shuttle"
	)
}

pub(crate) fn is_commit(revision: &str) -> bool {
	matches!(revision.len(), 40 | 64)
		&& revision
			.bytes()
			.all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn check_format_config(root: &Path, findings: &mut Findings) {
	let toolchain = root.join("rust-toolchain.toml");
	if let Some((table, _)) = read_manifest(&toolchain, findings)
		&& table
			.get("toolchain")
			.and_then(|table| table.get("channel"))
			.and_then(Value::as_str)
			!= Some(APP_VERSION)
	{
		findings.add(
			&toolchain,
			format_args!("toolchain.channel must pin {APP_VERSION}"),
		);
	}
	let rustfmt = root.join("rustfmt.toml");
	if let Some((table, _)) = read_manifest(&rustfmt, findings)
		&& (table.get("edition").and_then(Value::as_str) != Some(APP_EDITION)
			|| table.get("hard_tabs").and_then(Value::as_bool) != Some(true)
			|| table.get("tab_spaces").and_then(Value::as_integer) != Some(RUST_INDENT_WIDTH)
			|| table.get("max_width").and_then(Value::as_integer) != Some(RUST_MAX_WIDTH))
	{
		findings.add(
			&rustfmt,
			"rustfmt must use edition 2024, hard tabs, four-column tabs and width 100",
		);
	}
	let editor = root.join(".editorconfig");
	match fs::read_to_string(&editor) {
		Ok(contents) => check_editor_config(&editor, &contents, findings),
		Err(error) => findings.add(&editor, error),
	}
}

fn check_editor_config(path: &Path, contents: &str, findings: &mut Findings) {
	let mut section = "";
	let mut properties = std::collections::BTreeMap::new();
	for text in contents.lines().map(str::trim) {
		if text.starts_with('[') && text.ends_with(']') {
			section = text;
		} else if let Some((key, value)) = text.split_once('=') {
			properties.insert((section, key.trim()), value.trim());
		}
	}
	for (section, key, value) in [
		("", "root", "true"),
		("[*]", "end_of_line", "lf"),
		("[*]", "charset", "utf-8"),
		("[*]", "insert_final_newline", "true"),
		("[*.rs]", "indent_style", "tab"),
		("[*.rs]", "indent_size", "4"),
	] {
		if properties.get(&(section, key)) != Some(&value) {
			findings.add(path, format_args!("{section} {key} must be {value}"));
		}
	}
}

fn read_manifest(path: &Path, findings: &mut Findings) -> Option<(Table, String)> {
	let contents = match fs::read_to_string(path) {
		Ok(contents) => contents,
		Err(error) => {
			findings.add(path, error);
			return None;
		}
	};
	match contents.parse::<Table>() {
		Ok(table) => Some((table, contents)),
		Err(error) => {
			findings.add(path, error);
			None
		}
	}
}

#[cfg(test)]
mod tests;
