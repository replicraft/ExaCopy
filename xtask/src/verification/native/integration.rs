use std::path::{Component, Path, PathBuf};

use cargo_metadata::{Package, TargetKind};
use serde::Deserialize;
use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, Item, Lit, Meta, MetaNameValue, Token};

use super::{Case, artifact_text, command_identifier};
use crate::finding::Findings;

#[cfg(test)]
mod tests;

const CARGO_MANIFEST: &str = "Cargo.toml";

#[derive(Deserialize)]
struct CargoTargets {
	#[serde(default, rename = "test")]
	tests: Vec<TestDeclaration>,
}

#[derive(Deserialize)]
struct TestDeclaration {
	name: Option<String>,
	path: Option<String>,
	harness: Option<bool>,
	#[serde(default, rename = "required-features")]
	required_features: Vec<String>,
}

pub(super) fn check(
	workspace: &Path,
	package: &Package,
	root: &Path,
	manifest: &Path,
	case: &Case,
	findings: &mut Findings,
) {
	let Some(name) = case.test_target.as_deref().filter(|name| target_name(name)) else {
		findings.add(
			manifest,
			"native Rust integration case requires a valid test_target",
		);
		return;
	};
	if case.owner.is_some() || !case.ignored || !command_identifier(&case.selector) {
		findings.add(
			manifest,
			"native Rust integration case requires an owner-local, bare, ignored test selector",
		);
		return;
	}
	if !canonical_test_path(&case.source) {
		findings.add(
			manifest,
			"native Rust integration source must be canonical under tests/",
		);
		return;
	}
	let feature = case.required_feature.as_deref();
	if feature.is_some_and(|feature| !package.features.contains_key(feature)) {
		findings.add(
			manifest,
			"native test requires a feature declared by its owner",
		);
		return;
	}
	let path = root.join(&case.source);
	let mut candidates = package.targets.iter().filter(|target| {
		target.kind.as_slice() == [TargetKind::Test]
			&& target.name == name
			&& same_cargo_path(target.src_path.as_std_path(), &path)
	});
	if !candidates
		.next()
		.is_some_and(|target| target.test && exact_features(&target.required_features, feature))
		|| candidates.next().is_some()
	{
		findings.add(
			manifest,
			if feature.is_some() {
				"native Rust integration case needs an exact owner Cargo test target, source and required feature"
			} else {
				"native Rust integration case needs an exact owner Cargo test target and source with no required features"
			},
		);
		return;
	}
	if !standard_harness(workspace, package, root, name, case, findings) {
		return;
	}
	let Some(contents) = artifact_text(root, &case.source, findings) else {
		return;
	};
	if !has_linux_test(&contents, &case.selector, feature) {
		findings.add(
			&path,
			"expected exact crate-level Linux/profile cfg and a substantive top-level ignored libtest test",
		);
	}
}

// Cargo and an owned registry path can spell Windows separators differently.
// Compare every other unit exactly, including dot components and case.
#[cfg(windows)]
fn same_cargo_path(actual: &Path, expected: &Path) -> bool {
	use std::os::windows::ffi::OsStrExt as _;

	let separators = |unit| {
		if unit == u16::from(b'/') {
			u16::from(b'\\')
		} else {
			unit
		}
	};
	actual
		.as_os_str()
		.encode_wide()
		.map(separators)
		.eq(expected.as_os_str().encode_wide().map(separators))
}

#[cfg(not(windows))]
fn same_cargo_path(actual: &Path, expected: &Path) -> bool {
	actual.as_os_str() == expected.as_os_str()
}

fn exact_features(actual: &[String], expected: Option<&str>) -> bool {
	actual.iter().map(String::as_str).eq(expected)
}

fn target_name(name: &str) -> bool {
	name.as_bytes()
		.first()
		.is_some_and(u8::is_ascii_alphanumeric)
		&& name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn canonical_test_path(path: &Path) -> bool {
	let Some(raw) = path.to_str() else {
		return false;
	};
	path.starts_with("tests")
		&& path.extension().is_some_and(|extension| extension == "rs")
		&& !raw.contains('\\')
		&& raw.split('/').all(|part| !matches!(part, "" | "." | ".."))
		&& path
			.components()
			.all(|part| matches!(part, Component::Normal(_)))
}

fn standard_harness(
	workspace: &Path,
	package: &Package,
	root: &Path,
	name: &str,
	case: &Case,
	findings: &mut Findings,
) -> bool {
	let source = &case.source;
	let manifest = Path::new(CARGO_MANIFEST);
	let path = root.join(manifest);
	if !same_cargo_path(package.manifest_path.as_std_path(), &path) {
		findings.add(
			&path,
			"native Rust integration owner needs its canonical Cargo.toml",
		);
		return false;
	}
	let Ok(owned) = path.strip_prefix(workspace) else {
		findings.add(
			&path,
			"native Rust integration owner must be inside the workspace",
		);
		return false;
	};
	let Some(text) = artifact_text(workspace, owned, findings) else {
		return false;
	};
	let targets = match toml::from_str::<CargoTargets>(&text) {
		Ok(targets) => targets,
		Err(error) => {
			findings.add(&path, error);
			return false;
		}
	};
	// Cargo metadata does not expose the harness flag. An explicit target
	// can infer its name from its path. Compare both without trusting it as
	// an alternate source for the already selected metadata target.
	let mut explicit = targets.tests.iter().filter(|test| {
		test.name.as_deref() == Some(name)
			|| test
				.path
				.as_deref()
				.is_some_and(|path| canonical_lexical_target(&root.join(path)) == root.join(source))
	});
	let declaration = explicit.next();
	let valid = explicit.next().is_none()
		&& valid_declaration(declaration, name, source, case.required_feature.as_deref());
	if !valid {
		findings.add(
			&path,
			"native Rust integration target requires a standard libtest harness, canonical source and exact required features",
		);
	}
	valid
}

fn valid_declaration(
	declaration: Option<&TestDeclaration>,
	name: &str,
	source: &Path,
	feature: Option<&str>,
) -> bool {
	let Some(declaration) = declaration else {
		return feature.is_none();
	};
	let declared_path = declaration.path.as_deref();
	declaration.harness != Some(false)
		&& declared_path.is_none_or(|path| Some(path) == source.to_str())
		&& exact_features(&declaration.required_features, feature)
		&& (feature.is_none()
			|| (declaration.name.as_deref() == Some(name) && declared_path.is_some()))
}

fn canonical_lexical_target(path: &Path) -> PathBuf {
	let mut canonical = PathBuf::new();
	for item in path.components() {
		match item {
			Component::CurDir => {}
			Component::ParentDir if canonical.parent().is_some() => {
				canonical.pop();
			}
			_ => canonical.push(item.as_os_str()),
		}
	}
	canonical
}

fn has_linux_test(contents: &str, selector: &str, feature: Option<&str>) -> bool {
	syn::parse_file(contents).is_ok_and(|syntax| {
		let mut cfg = syntax
			.attrs
			.iter()
			.filter(|attr| attr.path().is_ident("cfg"));
		if !cfg.next().is_some_and(|attr| linux_cfg(attr, feature))
			|| cfg.next().is_some()
			|| syntax.attrs.iter().any(|attr| {
				attr.path().is_ident("cfg_attr")
					|| attr.path().is_ident("test_runner")
					|| attr.path().is_ident("reexport_test_harness_main")
					|| attr.path().is_ident("no_main")
			}) {
			return false;
		}
		let mut functions = syntax.items.iter().filter_map(|item| match item {
			Item::Fn(function) if function.sig.ident == selector => Some(function),
			_ => None,
		});
		functions.next().is_some_and(|function| {
			let signature = &function.sig;
			let mut tests = function
				.attrs
				.iter()
				.filter(|attr| attr.path().is_ident("test"));
			let mut ignores = function
				.attrs
				.iter()
				.filter(|attr| attr.path().is_ident("ignore"));
			tests
				.next()
				.is_some_and(|attr| matches!(attr.meta, Meta::Path(_)))
				&& tests.next().is_none()
				&& ignores.next().is_some_and(ignore_attribute)
				&& ignores.next().is_none()
				&& function.attrs.iter().all(|attr| {
					attr.path().is_ident("test")
						|| attr.path().is_ident("ignore")
						|| attr.path().is_ident("doc")
				})
				&& signature.asyncness.is_none()
				&& signature.unsafety.is_none()
				&& signature.constness.is_none()
				&& signature.abi.is_none()
				&& signature.inputs.is_empty()
				&& signature.generics.params.is_empty()
				&& !function.block.stmts.is_empty()
		}) && functions.next().is_none()
	})
}

fn linux_cfg(attr: &Attribute, feature: Option<&str>) -> bool {
	let Some(feature) = feature else {
		return attr
			.parse_args::<MetaNameValue>()
			.is_ok_and(|cfg| literal_cfg(&cfg, "target_os", "linux"));
	};
	attr.parse_args::<syn::MetaList>().is_ok_and(|cfg| {
		cfg.path.is_ident("all")
			&& cfg
				.parse_args_with(Punctuated::<MetaNameValue, Token![,]>::parse_terminated)
				.is_ok_and(|conditions| {
					let mut conditions = conditions.iter();
					conditions
						.next()
						.is_some_and(|condition| literal_cfg(condition, "target_os", "linux"))
						&& conditions
							.next()
							.is_some_and(|condition| literal_cfg(condition, "feature", feature))
						&& conditions.next().is_none()
				})
	})
}

fn literal_cfg(cfg: &MetaNameValue, key: &str, expected: &str) -> bool {
	cfg.path.is_ident(key)
		&& matches!(&cfg.value, Expr::Lit(value)
			if matches!(&value.lit, Lit::Str(value) if value.value() == expected))
}

fn ignore_attribute(attr: &Attribute) -> bool {
	match &attr.meta {
		Meta::Path(_) => true,
		Meta::NameValue(value) => {
			matches!(&value.value, Expr::Lit(value) if matches!(value.lit, Lit::Str(_)))
		}
		Meta::List(_) => false,
	}
}
