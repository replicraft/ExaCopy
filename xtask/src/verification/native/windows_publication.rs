use std::path::{Path, PathBuf};

use cargo_metadata::{CrateType, Package, TargetKind};
use syn::punctuated::Punctuated;
use syn::{Expr, Item, Lit, Meta, Token};

use super::{Case, CaseKind, Fixture, Profile, Target, artifact_text};
use crate::finding::Findings;

const OWNER: &str = "exacopy-platform";
const ID: &str = "windows-fixed-ntfs-publication";
pub(super) const FEATURE: &str = "experimental-windows-copy";
const MANIFEST: &str = "verification/windows_ntfs_publication/fixture.toml";
const RUNNER: &str = "verification/windows_ntfs_publication/run.ps1";
const CONTROLS: &str = "verification/windows_ntfs_publication/test_runner.ps1";
const WORKFLOW: &str = ".github/workflows/windows-ntfs-publication.yml";
const SOURCE: &str = "src/windows/stage/publication/tests.rs";
const PREFIX: &str = "windows::stage::publication::tests::";
const CASES: [&str; 5] = [
	"absent_target_moves_original_closed_stage",
	"late_incumbent_and_case_alias_are_preserved",
	"writer_and_changed_stage_refuse_before_rename",
	"bound_target_and_metadata_refusals_preserve_entries",
	"native_success_with_observation_failure_requires_reconciliation",
];

pub(super) fn applies(manifest: &Path, profile: Profile) -> bool {
	manifest == Path::new(MANIFEST) || matches!(profile, Profile::WindowsFixedNtfsPublication)
}

pub(super) fn check(
	workspace: &Path,
	package: &Package,
	root: &Path,
	manifest: &Path,
	fixture: &Fixture,
	findings: &mut Findings,
) {
	if !matches_fixture(package.name.as_str(), manifest, fixture) {
		findings.add(
			&root.join(manifest),
			"Windows publication needs its exact platform owner, paths and five ignored Rust unit cases",
		);
		return;
	}
	let library = root.join("src/lib.rs");
	if !package.targets.iter().any(|target| {
		target.name == "exacopy_platform"
			&& target.kind.as_slice() == [TargetKind::Lib]
			&& target.crate_types.as_slice() == [CrateType::Lib]
			&& target.test
			&& target.required_features.is_empty()
			&& separator_equivalent(target.src_path.as_std_path(), &library)
	}) || !package.features.contains_key(FEATURE)
	{
		findings.add(
			&root.join(manifest),
			"Windows publication needs the exact Cargo library harness and copy feature",
		);
	}
	check_module_chain(root, findings);
	check_cases(root, findings);
	check_runner(workspace, root, findings);
}

fn matches_fixture(owner: &str, manifest: &Path, fixture: &Fixture) -> bool {
	matches!(fixture.profile, Profile::WindowsFixedNtfsPublication)
		&& fixture.target == Target::WindowsX86_64Msvc
		&& owner == OWNER
		&& manifest.as_os_str() == MANIFEST
		&& fixture.id == ID
		&& fixture.runner.as_os_str() == RUNNER
		&& fixture.controls.as_os_str() == CONTROLS
		&& fixture.workflow.as_os_str() == WORKFLOW
		&& fixture.cases.len() == CASES.len()
		&& fixture
			.cases
			.iter()
			.zip(CASES)
			.all(|(case, leaf)| matches_case(case, leaf))
}

fn matches_case(case: &Case, leaf: &str) -> bool {
	matches!(case.kind, CaseKind::RustUnitWindows)
		&& case.owner.is_none()
		&& case.test_target.is_none()
		&& case.source.as_os_str() == SOURCE
		&& case.selector.strip_prefix(PREFIX) == Some(leaf)
		&& case.required_feature.as_deref() == Some(FEATURE)
		&& case.ignored
}

// Cargo may represent one Windows path with mixed separators. The fixed
// relative spelling in the manifest has its own separate checks.
fn separator_equivalent(left: &Path, right: &Path) -> bool {
	let normalized = |path: &Path| {
		path.to_str()
			.map(|text| text.replace(std::path::MAIN_SEPARATOR, "/"))
	};
	normalized(left).is_some_and(|path| normalized(right) == Some(path))
}

#[derive(Clone, Copy)]
enum Condition {
	Always,
	WindowsCopy,
	Test,
}

fn check_module_chain(root: &Path, findings: &mut Findings) {
	for (source, child, condition) in [
		("src/lib.rs", "windows", Condition::Always),
		("src/windows.rs", "stage", Condition::WindowsCopy),
		("src/windows/stage.rs", "publication", Condition::Always),
		("src/windows/stage/publication.rs", "tests", Condition::Test),
	] {
		let path = Path::new(source);
		let Some(contents) = artifact_text(root, path, findings) else {
			continue;
		};
		let valid = syn::parse_file(&contents).is_ok_and(|syntax| {
			let mut candidates = syntax.items.iter().filter_map(|item| match item {
				Item::Mod(module) if module.ident == child => Some(module),
				_ => None,
			});
			candidates.next().is_some_and(|module| {
				module.content.is_none()
					&& condition_matches(condition, &module.attrs)
					&& candidates.next().is_none()
			})
		});
		if !valid {
			findings.add(
				&root.join(path),
				format_args!(
					"Windows publication expects the exact external module {child} and its cfg"
				),
			);
		}
	}
}

fn condition_matches(condition: Condition, attributes: &[syn::Attribute]) -> bool {
	if attributes
		.iter()
		.any(|attr| attr.path().is_ident("path") || attr.path().is_ident("cfg_attr"))
	{
		return false;
	}
	let cfg = attributes
		.iter()
		.filter(|attr| attr.path().is_ident("cfg"))
		.collect::<Vec<_>>();
	match (condition, cfg.as_slice()) {
		(Condition::Always, []) => true,
		(Condition::Test, [cfg]) => cfg
			.parse_args::<Meta>()
			.is_ok_and(|meta| matches!(meta, Meta::Path(path) if path.is_ident("test"))),
		(Condition::WindowsCopy, [cfg]) => cfg
			.parse_args::<Meta>()
			.is_ok_and(|meta| matches!(meta, Meta::List(list) if windows_copy(&list))),
		_ => false,
	}
}

fn windows_copy(list: &syn::MetaList) -> bool {
	if !list.path.is_ident("all") {
		return false;
	}
	let Ok(parts) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated) else {
		return false;
	};
	let matches = |meta: &Meta, key, expected| {
		matches!(meta, Meta::NameValue(value) if value.path.is_ident(key)
			&& matches!(&value.value, Expr::Lit(value)
				if matches!(&value.lit, Lit::Str(value) if value.value() == expected)))
	};
	parts.len() == 2
		&& parts
			.iter()
			.any(|meta| matches(meta, "target_os", "windows"))
		&& parts.iter().any(|meta| matches(meta, "feature", FEATURE))
}

fn check_cases(root: &Path, findings: &mut Findings) {
	let path = Path::new(SOURCE);
	let Some(contents) = artifact_text(root, path, findings) else {
		return;
	};
	let syntax = syn::parse_file(&contents);
	for leaf in CASES {
		let valid = syntax.as_ref().is_ok_and(|syntax| {
			let mut candidates = syntax.items.iter().filter_map(|item| match item {
				Item::Fn(function) if function.sig.ident == leaf => Some(function),
				_ => None,
			});
			candidates.next().is_some_and(|function| {
				!function.block.stmts.is_empty()
					&& condition_matches(Condition::Always, &function.attrs)
					&& function
						.attrs
						.iter()
						.filter(|attr| attr.path().is_ident("test"))
						.count()
						== 1
					&& function
						.attrs
						.iter()
						.filter(|attr| attr.path().is_ident("ignore"))
						.count()
						== 1
					&& candidates.next().is_none()
			})
		});
		if !valid {
			findings.add(
				&root.join(path),
				format_args!("expected one substantive ignored Windows test {leaf}"),
			);
		}
	}
}

fn check_runner(workspace: &Path, root: &Path, findings: &mut Findings) {
	for source in [RUNNER, CONTROLS] {
		artifact_text(root, Path::new(source), findings);
	}
	let folder = Path::new(MANIFEST).parent().unwrap_or(Path::new(""));
	for helper in ["selection.ps1", "process.cs", "process-controls.ps1"] {
		artifact_text(root, &folder.join(helper), findings);
	}
	let workflow = Path::new(WORKFLOW);
	let Some(contents) = artifact_text(workspace, workflow, findings) else {
		return;
	};
	let runner_path = PathBuf::from("crates/platform/exacopy-platform").join(RUNNER);
	let runner_path = runner_path
		.to_string_lossy()
		.replace(std::path::MAIN_SEPARATOR, "/");
	if !contents
		.lines()
		.any(|line| line.trim() == "runs-on: windows-2025")
		|| !contents
			.lines()
			.any(|line| line.trim().strip_prefix("./") == Some(runner_path.as_str()))
		|| !contents.lines().any(|line| {
			line.trim() == "if: always() && steps.qualification.outputs.evidence_path != ''"
		}) {
		findings.add(
			&workspace.join(workflow),
			"Windows publication workflow needs its exact hosted image, owned runner and acquired artifact gate",
		);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn required_windows_copy_cfg_cannot_be_widened() {
		let correct: syn::Attribute = syn::parse_quote!(#[cfg(all(target_os = "windows", feature = "experimental-windows-copy"))]);
		let alternate_order: syn::Attribute = syn::parse_quote!(#[cfg(all(feature = "experimental-windows-copy", target_os = "windows"))]);
		let or: syn::Attribute = syn::parse_quote!(#[cfg(any(target_os = "windows", feature = "experimental-windows-copy"))]);
		let missing: syn::Attribute = syn::parse_quote!(#[cfg(target_os = "windows")]);
		let extra: syn::Attribute = syn::parse_quote!(#[cfg(all(target_os = "windows", feature = "experimental-windows-copy", test))]);
		let redirected: syn::Attribute = syn::parse_quote!(#[path = "other.rs"]);
		assert!(condition_matches(
			Condition::WindowsCopy,
			std::slice::from_ref(&correct)
		));
		assert!(condition_matches(
			Condition::WindowsCopy,
			&[alternate_order]
		));
		for invalid in [
			vec![or],
			vec![missing],
			vec![extra],
			vec![correct, redirected],
		] {
			assert!(!condition_matches(Condition::WindowsCopy, &invalid));
		}
	}

	#[test]
	fn manifest_profile_and_compiling_owner_must_match_reciprocally() {
		let mut fixture = Fixture {
			schema_version: 1,
			id: ID.to_owned(),
			target: Target::WindowsX86_64Msvc,
			profile: Profile::WindowsFixedNtfsPublication,
			rust_toolchain: crate::workspace::APP_VERSION.to_owned(),
			runner: RUNNER.into(),
			controls: CONTROLS.into(),
			workflow: WORKFLOW.into(),
			result: "result.json".into(),
			cases: CASES
				.into_iter()
				.map(|leaf| Case {
					kind: CaseKind::RustUnitWindows,
					owner: None,
					test_target: None,
					required_feature: Some(FEATURE.to_owned()),
					selector: format!("{PREFIX}{leaf}"),
					source: SOURCE.into(),
					ignored: true,
				})
				.collect(),
		};
		let exact = Path::new(MANIFEST);
		let alternate = Path::new("verification/other/fixture.toml");
		assert!(applies(exact, fixture.profile));
		assert!(applies(alternate, fixture.profile));
		assert!(matches_fixture(OWNER, exact, &fixture));
		assert!(!matches_fixture("exacopy-cli", exact, &fixture));
		assert!(!matches_fixture(OWNER, alternate, &fixture));
		fixture.target = Target::LinuxX86_64Gnu;
		assert!(!matches_fixture(OWNER, exact, &fixture));
		fixture.target = Target::WindowsX86_64Msvc;
		fixture.profile = Profile::UnprivilegedSameDeviceBind;
		assert!(applies(exact, fixture.profile));
		assert!(!applies(alternate, fixture.profile));
		assert!(!matches_fixture(OWNER, exact, &fixture));
	}

	#[test]
	fn exact_ignored_case_cannot_rebind_its_feature_or_harness_kind() {
		let mut case = Case {
			kind: CaseKind::RustUnitWindows,
			owner: None,
			test_target: None,
			required_feature: Some(FEATURE.to_owned()),
			selector: format!("{PREFIX}{}", CASES[0]),
			source: SOURCE.into(),
			ignored: true,
		};
		assert!(matches_case(&case, CASES[0]));
		case.kind = CaseKind::RustUnit;
		assert!(!matches_case(&case, CASES[0]));
		case.kind = CaseKind::RustUnitWindows;
		case.required_feature = Some("experimental-windows-read".to_owned());
		assert!(!matches_case(&case, CASES[0]));
		case.required_feature = Some(FEATURE.to_owned());
		case.ignored = false;
		assert!(!matches_case(&case, CASES[0]));
	}
}
