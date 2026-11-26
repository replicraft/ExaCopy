use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use cargo_metadata::Metadata;
use serde::Deserialize;

use crate::finding::Findings;

mod artifact;
mod native;
mod ownership;
const VERIFICATION_DIR: &str = "verification";
const OBLIGATIONS: &str = "obligations.toml";
const VERIFICATION_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Gate {
	Rust,
	Lean,
	Kani,
	Tlc,
}

impl std::fmt::Display for Gate {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let name = match self {
			Self::Rust => "rust",
			Self::Lean => "lean",
			Self::Kani => "kani",
			Self::Tlc => "tlc",
		};
		formatter.write_str(name)
	}
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
	schema_version: u32,
	#[serde(rename = "obligation")]
	obligations: Vec<Obligation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Obligation {
	pub(crate) id: String,
	#[serde(default)]
	pub(crate) requirement_ids: Vec<String>,
	pub(crate) source: PathBuf,
	symbols: Vec<String>,
	pub(crate) assumptions: Vec<String>,
	pub(crate) gates: Vec<Gate>,
	pub(crate) rust: Option<RustLink>,
	pub(crate) lean: Option<LeanLink>,
	pub(crate) kani: Option<KaniLink>,
	pub(crate) tlc: Option<TlcLink>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RustLink {
	#[serde(default)]
	pub(crate) features: Vec<String>,
	pub(crate) test: String,
	pub(crate) file: PathBuf,
	pub(crate) oracle: Option<String>,
	#[serde(default)]
	pub(crate) seeds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeanLink {
	pub(crate) theorem: String,
	proof: PathBuf,
	pub(crate) generated: PathBuf,
	pub(crate) oracle: Option<String>,
	#[serde(default)]
	pub(crate) axioms_tcb: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KaniLink {
	pub(crate) harness: String,
	pub(crate) file: PathBuf,
	pub(crate) unwind_bound: u32,
	pub(crate) oracle: Option<String>,
	#[serde(default)]
	pub(crate) model_bounds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlcLink {
	pub(crate) spec: PathBuf,
	pub(crate) config: PathBuf,
	pub(crate) negative_control: PathBuf,
	pub(crate) oracle: Option<String>,
	#[serde(default)]
	pub(crate) model_bounds: Vec<String>,
	#[serde(default)]
	pub(crate) fairness: Vec<String>,
	#[serde(default)]
	pub(crate) seeds: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct Project {
	pub(crate) package_name: String,
	pub(crate) root: PathBuf,
	pub(crate) obligations: Vec<Obligation>,
}

pub(crate) fn check(
	metadata: &Metadata,
	files: &[PathBuf],
	findings: &mut Findings,
) -> Vec<Project> {
	let mut projects = Vec::new();
	let mut ids = BTreeSet::new();
	let mut fixture_ids = BTreeSet::new();
	let mut verification_roots = Vec::new();
	let root = metadata.workspace_root.as_std_path();
	let Some(mut inventory) = ownership::Inventory::load(root, findings) else {
		return projects;
	};
	for package in metadata.workspace_packages() {
		let Some(root) = package.manifest_path.as_std_path().parent() else {
			findings.add(
				package.manifest_path.as_std_path(),
				"member has no parent directory",
			);
			continue;
		};
		let verification = root.join(VERIFICATION_DIR);
		let native = inventory.native_fixtures.remove(package.name.as_str());
		if let Some(manifests) = &native {
			native::check(
				metadata.workspace_root.as_std_path(),
				package,
				root,
				manifests,
				&mut fixture_ids,
				findings,
			);
		}
		let Some(required_gates) = inventory.owners.remove(package.name.as_str()) else {
			let unauthorized = if native.is_some() {
				verification.join(OBLIGATIONS)
			} else {
				verification
			};
			match fs::symlink_metadata(&unauthorized) {
				Ok(_) => findings.add(
					&unauthorized,
					format_args!("{} must register its verification ownership", package.name),
				),
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => findings.add(&unauthorized, error),
			}
			continue;
		};
		let ledger = verification.join(OBLIGATIONS);
		let script = Path::new("verification/check.sh");
		check_script(root, script, findings);
		let Some(manifest) = load_manifest(root, findings) else {
			continue;
		};
		for gate in required_gates {
			if !manifest
				.obligations
				.iter()
				.any(|entry| entry.gates.contains(&gate))
			{
				findings.add(
					&ledger,
					format_args!("{} must declare the {gate} gate", package.name),
				);
			}
		}
		verification_roots.push(verification);
		for entry in &manifest.obligations {
			if !ids.insert(entry.id.clone()) {
				findings.add(
					&ledger,
					format_args!("duplicate obligation ID {}", entry.id),
				);
			}
			if let Some(link) = &entry.rust {
				let features = link.features.iter().collect::<BTreeSet<_>>();
				if features.len() != link.features.len() {
					findings.add(
						&ledger,
						format_args!("{} has duplicate Rust gate features", entry.id),
					);
				}
				for feature in features {
					if !package.features.contains_key(feature) {
						findings.add(
							&ledger,
							format_args!(
								"{} names an undeclared Rust gate feature {feature:?} of {}",
								entry.id, package.name
							),
						);
					}
				}
			}
			check_obligation(root, &ledger, entry, findings);
		}
		projects.push(Project {
			package_name: package.name.to_string(),
			root: root.to_path_buf(),
			obligations: manifest.obligations,
		});
	}
	for owner in inventory.owners.keys() {
		findings.add(
			root,
			format_args!("missing verification owner workspace member {owner}"),
		);
	}
	for owner in inventory.native_fixtures.keys() {
		findings.add(
			root,
			format_args!("missing native fixture owner workspace member {owner}"),
		);
	}
	if root.join("proofs").exists() || root.join(VERIFICATION_DIR).exists() {
		findings.add(
			root,
			"formal verification projects belong in each crate's verification directory",
		);
	}
	for file in files.iter().filter(|path| is_formal_asset(path)) {
		let owner = verification_roots
			.iter()
			.find(|owner| file.starts_with(owner));
		if owner.is_none_or(|owner| !artifact::owned_location(owner, file)) {
			findings.add(
				file,
				"formal verification artifact is outside its owning crate's verification layout",
			);
		}
	}
	projects
}

fn is_formal_asset(path: &Path) -> bool {
	path.extension()
		.and_then(|extension| extension.to_str())
		.is_some_and(|ext| matches!(ext, "lean" | "tla"))
		|| path
			.file_name()
			.and_then(|name| name.to_str())
			.is_some_and(|name| {
				matches!(
					name,
					OBLIGATIONS | "lakefile.toml" | "lake-manifest.json" | "lean-toolchain"
				)
			})
		|| path.components().any(|component| {
			component.as_os_str() == "kani" && path.extension().is_some_and(|ext| ext == "rs")
		})
}

fn load_manifest(root: &Path, findings: &mut Findings) -> Option<Manifest> {
	let relative = Path::new(VERIFICATION_DIR).join(OBLIGATIONS);
	let path = root.join(&relative);
	let contents = artifact_text(root, &relative, findings)?;
	match toml::from_str::<Manifest>(&contents) {
		Ok(manifest) => {
			if manifest.schema_version != VERIFICATION_SCHEMA || manifest.obligations.is_empty() {
				findings.add(
					&path,
					"expected schema_version 1 and at least one obligation",
				);
			}
			Some(manifest)
		}
		Err(error) => {
			findings.add(&path, error);
			None
		}
	}
}

fn check_script(root: &Path, script: &Path, findings: &mut Findings) {
	if let Some(contents) = artifact_text(root, script, findings)
		&& (!contents.starts_with("#!")
			|| contents
				.lines()
				.filter(|line| {
					let line = line.trim();
					!line.is_empty() && !line.starts_with('#')
				})
				.count()
				== 0)
	{
		findings.add(
			&root.join(script),
			"expected a substantive reproducible verification script",
		);
	}
}

fn check_obligation(root: &Path, ledger: &Path, entry: &Obligation, findings: &mut Findings) {
	if !numbered_id(&entry.id, "P-") {
		findings.add(ledger, format_args!("invalid obligation ID {}", entry.id));
	}
	if entry
		.requirement_ids
		.iter()
		.any(|id| !numbered_id(id, "R-"))
		|| entry.requirement_ids.iter().collect::<BTreeSet<_>>().len()
			!= entry.requirement_ids.len()
	{
		findings.add(
			ledger,
			format_args!("{} contains invalid or duplicate requirement IDs", entry.id),
		);
	}
	if entry.symbols.is_empty()
		|| entry.symbols.iter().any(|symbol| symbol.trim().is_empty())
		|| entry.assumptions.iter().any(|note| note.trim().is_empty())
	{
		findings.add(
			ledger,
			format_args!(
				"{} needs source symbols and substantive assumption entries",
				entry.id
			),
		);
	}
	let active = entry.gates.iter().copied().collect::<BTreeSet<_>>();
	if active.is_empty() || active.len() != entry.gates.len() {
		findings.add(
			ledger,
			format_args!(
				"{} must declare unique, nonempty verification gates",
				entry.id
			),
		);
	}
	if !entry.source.starts_with("src") && !entry.source.starts_with(VERIFICATION_DIR) {
		findings.add(
			ledger,
			format_args!("{} source belongs under src/ or verification/", entry.id),
		);
	} else {
		artifact::check_symbols(root, &entry.source, &entry.symbols, findings);
	}
	for (gate, link) in [
		(Gate::Rust, entry.rust.is_some()),
		(Gate::Lean, entry.lean.is_some()),
		(Gate::Kani, entry.kani.is_some()),
		(Gate::Tlc, entry.tlc.is_some()),
	] {
		if active.contains(&gate) != link {
			findings.add(
				ledger,
				format_args!(
					"{} needs a {gate} link exactly when that gate is declared",
					entry.id
				),
			);
		}
	}
	if let Some(link) = &entry.rust {
		artifact::check_rust(root, link, findings);
	}
	if let Some(link) = &entry.lean {
		artifact::check_lean(root, link, findings);
	}
	if let Some(link) = &entry.kani {
		artifact::check_kani(root, link, findings);
	}
	if let Some(link) = &entry.tlc {
		artifact::check_tlc(root, link, findings);
	}
}

pub(crate) fn numbered_id(text: &str, prefix: &str) -> bool {
	const MIN_ID_DIGITS: usize = 3;
	text.strip_prefix(prefix).is_some_and(|digits| {
		digits.len() >= MIN_ID_DIGITS && digits.bytes().all(|byte| byte.is_ascii_digit())
	})
}

pub(crate) fn owned_file(root: &Path, relative: &Path) -> std::io::Result<PathBuf> {
	if !relative
		.components()
		.all(|part| matches!(part, Component::Normal(_)))
	{
		return Err(std::io::Error::other(
			"path must be relative without parent or current-directory components",
		));
	}
	let mut path = root.to_path_buf();
	for part in relative.components() {
		path.push(part);
		if fs::symlink_metadata(&path)?.is_symlink() {
			return Err(std::io::Error::other(
				"linked artifacts must be owned regular files without symlinks",
			));
		}
	}
	if !path.is_file() {
		return Err(std::io::Error::other("expected an owned regular file"));
	}
	Ok(path)
}

fn artifact_text(root: &Path, relative: &Path, findings: &mut Findings) -> Option<String> {
	match owned_file(root, relative).and_then(fs::read_to_string) {
		Ok(contents) if !contents.trim().is_empty() => Some(contents),
		Ok(_) => {
			findings.add(&root.join(relative), "artifact must be substantive");
			None
		}
		Err(error) => {
			findings.add(&root.join(relative), error);
			None
		}
	}
}

#[cfg(test)]
mod tests;
