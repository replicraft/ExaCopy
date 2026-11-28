use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use cargo_metadata::{Metadata, Package, TargetKind};
use serde::Deserialize;
use syn::{Expr, Item, Lit, MetaNameValue};

use super::artifact_text;
use crate::finding::Findings;
use crate::workspace::APP_VERSION;

mod closed_ext4;
mod custody;
mod genesis;
mod integration;
mod linked_unit;
mod managed_sync;
mod public_stage;
mod windows_publication;

const FIXTURE_MANIFEST: &str = "fixture.toml";
const RESULT: &str = "result.json";
const STATMOUNT_FEATURE: &str = "experimental-linux-managed-sync";

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
enum Target {
	#[serde(rename = "x86_64-unknown-linux-gnu")]
	LinuxX86_64Gnu,
	#[serde(rename = "x86_64-pc-windows-msvc")]
	WindowsX86_64Msvc,
}

impl Target {
	fn triple(self) -> &'static str {
		match self {
			Self::LinuxX86_64Gnu => "x86_64-unknown-linux-gnu",
			Self::WindowsX86_64Msvc => "x86_64-pc-windows-msvc",
		}
	}
}

#[derive(Clone, Copy, Deserialize)]
enum Profile {
	#[serde(rename = "linux-unprivileged-same-device-bind-v1")]
	UnprivilegedSameDeviceBind,
	#[serde(rename = "linux-hosted-root-setup-unprivileged-observer-v1")]
	HostedRootSetupUnprivilegedObserver,
	#[serde(rename = "linux-unprivileged-tmpfs-sync-preview-v1")]
	UnprivilegedTmpfsSyncPreview,
	#[serde(rename = "linux-unprivileged-whole-ext4-sync-history-v1")]
	UnprivilegedWholeExt4SyncHistory,
	#[serde(rename = "linux-unprivileged-whole-ext4-witnessed-components-v1")]
	UnprivilegedWholeExt4WitnessedComponents,
	#[serde(rename = "linux-unprivileged-whole-ext4-sync-statmount-v1")]
	UnprivilegedWholeExt4SyncStatmount,
	#[serde(rename = "linux-unprivileged-whole-ext4-managed-sync-production-v1")]
	UnprivilegedWholeExt4ManagedSyncProduction,
	#[serde(rename = "linux-unprivileged-whole-ext4-managed-sync-genesis-production-v1")]
	UnprivilegedWholeExt4ManagedSyncGenesisProduction,
	#[serde(rename = "linux-unprivileged-whole-ext4-public-stage-v1")]
	UnprivilegedWholeExt4PublicStage,
	#[serde(rename = "windows-hosted-server2025-fixed-ntfs-publication-v1")]
	WindowsFixedNtfsPublication,
	#[serde(rename = "windows-hosted-server2025-fixed-ntfs-publication-owned-preparation-v2")]
	WindowsFixedNtfsPublicationOwnedPreparation,
}

impl Profile {
	fn target(self) -> Target {
		match self {
			Self::UnprivilegedSameDeviceBind
			| Self::HostedRootSetupUnprivilegedObserver
			| Self::UnprivilegedTmpfsSyncPreview
			| Self::UnprivilegedWholeExt4SyncHistory
			| Self::UnprivilegedWholeExt4WitnessedComponents
			| Self::UnprivilegedWholeExt4SyncStatmount
			| Self::UnprivilegedWholeExt4ManagedSyncProduction
			| Self::UnprivilegedWholeExt4ManagedSyncGenesisProduction
			| Self::UnprivilegedWholeExt4PublicStage => Target::LinuxX86_64Gnu,
			Self::WindowsFixedNtfsPublication
			| Self::WindowsFixedNtfsPublicationOwnedPreparation => Target::WindowsX86_64Msvc,
		}
	}

	fn integration(self) -> bool {
		matches!(
			self,
			Self::UnprivilegedWholeExt4SyncHistory
				| Self::UnprivilegedWholeExt4SyncStatmount
				| Self::UnprivilegedWholeExt4ManagedSyncProduction
				| Self::UnprivilegedWholeExt4ManagedSyncGenesisProduction
		)
	}

	fn required_feature(self) -> Option<&'static str> {
		match self {
			Self::UnprivilegedWholeExt4SyncStatmount => Some(STATMOUNT_FEATURE),
			Self::UnprivilegedWholeExt4ManagedSyncProduction
			| Self::UnprivilegedWholeExt4ManagedSyncGenesisProduction => Some(managed_sync::FEATURE),
			Self::WindowsFixedNtfsPublication
			| Self::WindowsFixedNtfsPublicationOwnedPreparation => Some(windows_publication::FEATURE),
			_ => None,
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
	prepared_component_feature: Option<String>,
	#[serde(rename = "case")]
	cases: Vec<Case>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CaseKind {
	#[default]
	RustUnit,
	RustUnitWindows,
	RustIntegration,
	Command,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
	#[serde(default)]
	kind: CaseKind,
	owner: Option<String>,
	test_target: Option<String>,
	required_feature: Option<String>,
	selector: String,
	source: PathBuf,
	ignored: bool,
}

pub(super) fn check(
	metadata: &Metadata,
	package: &Package,
	root: &Path,
	manifests: &[PathBuf],
	ids: &mut BTreeSet<String>,
	findings: &mut Findings,
) {
	if !has_default_library(package, root) {
		findings.add(
			root,
			"native fixture owner must have a src/lib.rs library target",
		);
	}
	for manifest in manifests {
		check_manifest(metadata, package, root, manifest, ids, findings);
	}
}

fn has_default_library(package: &Package, root: &Path) -> bool {
	let lib = root.join("src/lib.rs");
	package.targets.iter().any(|target| {
		target.kind.contains(&TargetKind::Lib) && target.src_path.as_std_path() == lib.as_path()
	})
}

fn check_manifest(
	metadata: &Metadata,
	package: &Package,
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

	if !managed_sync::check(package, manifest, &path, &fixture, findings) {
		return;
	}

	if windows_publication::applies(manifest, fixture.profile) {
		windows_publication::check(
			metadata.workspace_root.as_std_path(),
			package,
			root,
			manifest,
			&fixture,
			findings,
		);
		return;
	}

	if !genesis::check(package, manifest, &path, &fixture, findings)
		|| !closed_ext4::check(package, manifest, &path, &fixture, findings)
		|| !public_stage::check(package, manifest, &path, &fixture, findings)
	{
		return;
	}

	custody::check(
		metadata.workspace_root.as_std_path(),
		root,
		manifest,
		&fixture,
		findings,
	);
	check_cases(metadata, package, root, &path, &fixture, findings);
}

fn check_cases(
	metadata: &Metadata,
	package: &Package,
	root: &Path,
	manifest: &Path,
	fixture: &Fixture,
	findings: &mut Findings,
) {
	if fixture.cases.is_empty() {
		findings.add(manifest, "native fixture needs exact test cases");
	}
	let mut selectors = BTreeSet::new();
	for case in &fixture.cases {
		if !selectors.insert(&case.selector) {
			findings.add(
				manifest,
				format_args!("duplicate native test selector {}", case.selector),
			);
			continue;
		}
		if !matches!(case.kind, CaseKind::RustIntegration) && case.test_target.is_some() {
			findings.add(
				manifest,
				"test_target is only valid for a native Rust integration case",
			);
			continue;
		}
		if case.required_feature.as_deref() != fixture.profile.required_feature() {
			findings.add(
				manifest,
				"native fixture feature must match its exact profile",
			);
			continue;
		}
		if fixture.profile.integration() != matches!(case.kind, CaseKind::RustIntegration) {
			findings.add(
				manifest,
				"native Rust integration cases require a closed whole-ext4 fixture profile",
			);
			continue;
		}
		match case.kind {
			CaseKind::RustIntegration => integration::check(
				metadata.workspace_root.as_std_path(),
				package,
				root,
				manifest,
				case,
				findings,
			),
			CaseKind::RustUnit => {
				check_rust_case(metadata, package, manifest, fixture.profile, case, findings);
			}
			CaseKind::RustUnitWindows => findings.add(
				manifest,
				"Windows native unit cases require the closed fixed-NTFS publication profile",
			),
			CaseKind::Command => {
				if case.owner.is_some()
					|| case.ignored
					|| case.source != fixture.runner
					|| !command_identifier(&case.selector)
				{
					findings.add(
						manifest,
						format_args!(
							"native command case {} needs an identifier, the declared runner, and no owner override or ignore",
							case.selector
						),
					);
				}
			}
		}
	}
}

fn command_identifier(selector: &str) -> bool {
	let mut bytes = selector.bytes();
	bytes
		.next()
		.is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
		&& selector != "_"
		&& bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn check_rust_case(
	metadata: &Metadata,
	package: &Package,
	manifest: &Path,
	profile: Profile,
	case: &Case,
	findings: &mut Findings,
) {
	let Some(owner) = case.owner.as_deref().map_or(Some(package), |name| {
		metadata
			.workspace_packages()
			.into_iter()
			.find(|member| member.name.as_str() == name)
	}) else {
		findings.add(
			manifest,
			format_args!(
				"unknown workspace owner for native Rust test {}",
				case.selector
			),
		);
		return;
	};
	let Some(root) = owner.manifest_path.as_std_path().parent() else {
		findings.add(manifest, "native Rust test owner has no package root");
		return;
	};
	if !has_default_library(owner, root) {
		findings.add(
			root,
			"native Rust test owner must have a src/lib.rs library target",
		);
		return;
	}
	if case.source.starts_with("tests/unit") {
		linked_unit::check(root, manifest, case, findings);
		return;
	}
	let app_stage = public_stage::matches_case(owner.name.as_str(), profile, case);
	let Some((modules, leaf)) = selector(&case.source, &case.selector, app_stage) else {
		findings.add(
			manifest,
			format_args!("invalid native test selector {}", case.selector),
		);
		return;
	};
	if !check_module_chain(root, &modules, usize::from(app_stage), findings) {
		return;
	}
	let Some(contents) = artifact_text(root, &case.source, findings) else {
		return;
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

fn selector(source: &Path, selector: &str, app_stage: bool) -> Option<(Vec<String>, String)> {
	let accepted_root = app_stage || source.starts_with("src/linux");
	if !accepted_root || source.extension() != Some(OsStr::new("rs")) {
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

fn check_module_chain(
	root: &Path,
	modules: &[String],
	linux_module: usize,
	findings: &mut Findings,
) -> bool {
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
					&& (index != linux_module
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
