use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use cargo_metadata::{Package, TargetKind};
use serde::Deserialize;
use syn::{Expr, Item, Lit, MetaNameValue};

use super::artifact_text;
use crate::finding::Findings;
use crate::workspace::APP_VERSION;

const FIXTURE_MANIFEST: &str = "fixture.toml";
const RESULT: &str = "result.json";

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
enum Target {
	#[serde(rename = "x86_64-unknown-linux-gnu")]
	LinuxX86_64Gnu,
}

impl Target {
	fn triple(self) -> &'static str {
		match self {
			Self::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
		}
	}
}

#[derive(Clone, Copy, Deserialize)]
enum Profile {
	#[serde(rename = "linux-unprivileged-same-device-bind-v1")]
	LinuxUnprivilegedSameDeviceBind,
}

impl Profile {
	fn target(self) -> Target {
		match self {
			Self::LinuxUnprivilegedSameDeviceBind => Target::LinuxX86_64Gnu,
		}
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
	schema_version: u32,
	id: String,
	target: Target,
	profile: Profile,
	rust_toolchain: String,
	runner: PathBuf,
	controls: PathBuf,
	workflow: PathBuf,
	result: PathBuf,
	#[serde(rename = "case")]
	cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
	selector: String,
	source: PathBuf,
	ignored: bool,
}

pub(super) fn check(
	workspace: &Path,
	package: &Package,
	root: &Path,
	manifests: &[PathBuf],
	ids: &mut BTreeSet<String>,
	findings: &mut Findings,
) {
	let lib = root.join("src/lib.rs");
	if !package.targets.iter().any(|target| {
		target.kind.contains(&TargetKind::Lib) && target.src_path.as_std_path() == lib.as_path()
	}) {
		findings.add(
			root,
			"native fixture owner must have a src/lib.rs library target",
		);
	}
	for manifest in manifests {
		check_manifest(workspace, root, manifest, ids, findings);
	}
}

fn check_manifest(
	workspace: &Path,
	root: &Path,
	manifest: &Path,
	ids: &mut BTreeSet<String>,
	findings: &mut Findings,
) {
	let path = root.join(manifest);
	if !manifest.starts_with("verification")
		|| manifest.components().count() < 3
		|| manifest.file_name() != Some(OsStr::new(FIXTURE_MANIFEST))
	{
		findings.add(
			&path,
			"native fixture must own verification/<fixture>/fixture.toml",
		);
		return;
	}
	let Some(contents) = artifact_text(root, manifest, findings) else {
		return;
	};
	let fixture = match toml::from_str::<Fixture>(&contents) {
		Ok(fixture) => fixture,
		Err(error) => {
			findings.add(&path, error);
			return;
		}
	};
	let valid_id = !fixture.id.is_empty()
		&& fixture.id.split('-').all(|part| {
			!part.is_empty()
				&& part
					.bytes()
					.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
		});
	if fixture.schema_version != 1 || !valid_id || !ids.insert(fixture.id.clone()) {
		findings.add(
			&path,
			"native fixture needs schema version 1 and a unique kebab-case ID",
		);
	}
	if fixture.profile.target() != fixture.target
		|| fixture.rust_toolchain != APP_VERSION
		|| fixture.result.as_path() != Path::new(RESULT)
	{
		findings.add(
			&path,
			"native fixture target, toolchain or result does not match its profile",
		);
	}

	check_custody(workspace, root, manifest, &fixture, findings);
	check_cases(root, &path, &fixture.cases, findings);
}

fn check_custody(
	workspace: &Path,
	root: &Path,
	manifest: &Path,
	fixture: &Fixture,
	findings: &mut Findings,
) {
	if fixture.runner == fixture.controls {
		findings.add(
			&root.join(manifest),
			"native fixture runner and controls must be distinct",
		);
	}
	for python in [&fixture.runner, &fixture.controls] {
		if python.parent() != manifest.parent() || python.extension() != Some(OsStr::new("py")) {
			findings.add(
				&root.join(python),
				"expected Python fixture source beside the manifest",
			);
		} else {
			artifact_text(root, python, findings);
		}
	}
	let workflow = &fixture.workflow;
	if workflow.parent() != Some(Path::new(".github/workflows"))
		|| workflow.extension() != Some(OsStr::new("yml"))
	{
		findings.add(
			&workspace.join(workflow),
			"native workflow must be under .github/workflows",
		);
		return;
	}
	let Some(contents) = artifact_text(workspace, workflow, findings) else {
		return;
	};
	let expected_host = format!("EXPECTED_RUST_HOST: {}", fixture.target.triple());
	let referenced = |file: &Path| {
		let path = root.join(file);
		path.strip_prefix(workspace).is_ok_and(|path| {
			let posix = path
				.to_string_lossy()
				.replace(std::path::MAIN_SEPARATOR, "/");
			contents
				.lines()
				.filter(|line| !line.trim_start().starts_with('#'))
				.flat_map(str::split_whitespace)
				.any(|token| token.trim_matches(['\'', '"']) == posix.as_str())
		})
	};
	if !contents.lines().any(|line| line.trim() == expected_host)
		|| !referenced(&fixture.runner)
		|| !referenced(&fixture.controls)
	{
		findings.add(
			&workspace.join(workflow),
			"native workflow must reference the declared target, runner and controls",
		);
	}
}

fn check_cases(root: &Path, manifest: &Path, cases: &[Case], findings: &mut Findings) {
	if cases.is_empty() {
		findings.add(manifest, "native fixture needs exact test cases");
	}
	let mut selectors = BTreeSet::new();
	for case in cases {
		let Some((modules, leaf)) = selector(&case.source, &case.selector) else {
			findings.add(
				manifest,
				format_args!("invalid native test selector {}", case.selector),
			);
			continue;
		};
		if !selectors.insert(&case.selector) {
			findings.add(
				manifest,
				format_args!("duplicate native test selector {}", case.selector),
			);
			continue;
		}
		if !check_module_chain(root, &modules, findings) {
			continue;
		}
		let Some(contents) = artifact_text(root, &case.source, findings) else {
			continue;
		};
		let matches = syn::parse_file(&contents).is_ok_and(|syntax| {
			syntax.items.iter().any(|item| {
				let Item::Fn(function) = item else {
					return false;
				};
				function.sig.ident == leaf
					&& !function.block.stmts.is_empty()
					&& function
						.attrs
						.iter()
						.any(|attr| attr.path().is_ident("test"))
					&& function
						.attrs
						.iter()
						.any(|attr| attr.path().is_ident("ignore"))
						== case.ignored
			})
		});
		if !matches {
			findings.add(
				&root.join(&case.source),
				format_args!(
					"expected native #[test] with declared ignore state for {}",
					case.selector
				),
			);
		}
	}
}

fn selector(source: &Path, selector: &str) -> Option<(Vec<String>, String)> {
	if source.extension() != Some(OsStr::new("rs")) || !source.starts_with("src/linux") {
		return None;
	}
	let stem = source.strip_prefix("src").ok()?.with_extension("");
	let modules = stem
		.iter()
		.map(|part| part.to_str().map(str::to_owned))
		.collect::<Option<Vec<_>>>()?;
	let (scope, leaf) = selector.rsplit_once("::")?;
	(scope == modules.join("::") && syn::parse_str::<syn::Ident>(leaf).is_ok())
		.then(|| (modules, leaf.to_owned()))
}

fn check_module_chain(root: &Path, modules: &[String], findings: &mut Findings) -> bool {
	let mut directory = PathBuf::from("src");
	let mut parent = directory.join("lib.rs");
	for (index, module) in modules.iter().enumerate() {
		let Some(contents) = artifact_text(root, &parent, findings) else {
			return false;
		};
		let found = syn::parse_file(&contents).is_ok_and(|syntax| {
			syntax.items.iter().any(|item| {
				let Item::Mod(decl) = item else {
					return false;
				};
				decl.ident == module.as_str()
					&& decl.content.is_none()
					&& !decl.attrs.iter().any(|attr| {
						attr.path().is_ident("path") || attr.path().is_ident("cfg_attr")
					})
					&& (index != 0
						|| decl.attrs.iter().any(|attr| {
							attr.path().is_ident("cfg")
								&& attr.parse_args::<MetaNameValue>().is_ok_and(|cfg| {
									cfg.path.is_ident("target_os")
										&& matches!(&cfg.value, Expr::Lit(value)
											if matches!(&value.lit, Lit::Str(os) if os.value() == "linux"))
								})
						}))
			})
		});
		if !found {
			findings.add(
				&root.join(&parent),
				format_args!("missing native module declaration {module}"),
			);
			return false;
		}
		directory.push(module);
		parent = directory.with_extension("rs");
	}
	true
}
