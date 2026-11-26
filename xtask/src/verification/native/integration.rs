use std::path::{Component, Path, PathBuf};

use cargo_metadata::{Package, TargetKind};
use serde::Deserialize;
use syn::{Attribute, Expr, Item, Lit, Meta, MetaNameValue};

use super::{Case, artifact_text, command_identifier};
use crate::finding::Findings;

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
	let path = root.join(&case.source);
	let mut candidates = package.targets.iter().filter(|target| {
		target.kind.as_slice() == [TargetKind::Test]
			&& target.name == name
			&& target.src_path.as_std_path().as_os_str() == path.as_os_str()
	});
	if !candidates
		.next()
		.is_some_and(|target| target.test && target.required_features.is_empty())
		|| candidates.next().is_some()
	{
		findings.add(
			manifest,
			"native Rust integration case needs an exact owner Cargo test target and source with no required features",
		);
		return;
	}
	if !standard_harness(workspace, package, root, name, &case.source, findings) {
		return;
	}
	let Some(contents) = artifact_text(root, &case.source, findings) else {
		return;
	};
	if !has_linux_test(&contents, &case.selector) {
		findings.add(
			&path,
			"expected exact crate-level Linux cfg and a substantive top-level ignored libtest test",
		);
	}
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
	source: &Path,
	findings: &mut Findings,
) -> bool {
	let manifest = Path::new(CARGO_MANIFEST);
	let path = root.join(manifest);
	if package.manifest_path.as_std_path().as_os_str() != path.as_os_str() {
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
	let valid = explicit.next().is_none_or(|test| {
		test.harness != Some(false)
			&& test
				.path
				.as_deref()
				.is_none_or(|path| Some(path) == source.to_str())
	}) && explicit.next().is_none();
	if !valid {
		findings.add(
			&path,
			"native Rust integration target requires a standard libtest harness and canonical source",
		);
	}
	valid
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

fn has_linux_test(contents: &str, selector: &str) -> bool {
	syn::parse_file(contents).is_ok_and(|syntax| {
		let mut cfg = syntax
			.attrs
			.iter()
			.filter(|attr| attr.path().is_ident("cfg"));
		if !cfg.next().is_some_and(linux_cfg)
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

fn linux_cfg(attr: &Attribute) -> bool {
	attr.parse_args::<MetaNameValue>().is_ok_and(|cfg| {
		cfg.path.is_ident("target_os")
			&& matches!(&cfg.value, Expr::Lit(value)
				if matches!(&value.lit, Lit::Str(os) if os.value() == "linux"))
	})
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
