//! Check that every inventoried contract has the declared status and source markers.

mod markers;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::finding::Findings;

const INVENTORY: &str = "docs/specs/contracts/versions.toml";
const POLICY: &str = "docs/architecture/contract-versioning.md";
const INVENTORY_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
	CliOutput,
	LocalProfile,
	TransferJournal,
	Configuration,
	ConnectionProfile,
	Repository,
	Manifest,
	Ipc,
	Mcp,
	RemoteProtocol,
	LibraryApi,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
	Implemented,
	ImplementedPrivate,
	DevelopmentUnversioned,
	Development,
	Planned,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
	inventory_version: u16,
	policy: PathBuf,
	contract: Vec<Contract>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Contract {
	id: String,
	kind: Kind,
	status: Status,
	version: Option<String>,
	owner: Option<PathBuf>,
	magic: Option<String>,
	required_features: Option<u64>,
	notes: Option<String>,
}

const PLANNED: &[(&str, Kind)] = &[
	("configuration-schema", Kind::Configuration),
	("saved-connection-profiles", Kind::ConnectionProfile),
	("backup-repository", Kind::Repository),
	("portable-manifests", Kind::Manifest),
	("ipc", Kind::Ipc),
	("mcp", Kind::Mcp),
	("native-remote", Kind::RemoteProtocol),
];

/// Validate the checked-in contract inventory and its implementation anchors.
pub(crate) fn check(root: &Path, findings: &mut Findings) {
	let path = root.join(INVENTORY);
	match fs::read_to_string(&path) {
		Ok(text) => check_text(root, &path, &text, findings),
		Err(error) => findings.add(&path, error),
	}
}

fn check_text(root: &Path, path: &Path, text: &str, findings: &mut Findings) {
	let inventory: Inventory = match toml::from_str(text) {
		Ok(inventory) => inventory,
		Err(error) => {
			findings.add(path, error);
			return;
		}
	};
	if inventory.inventory_version != INVENTORY_VERSION {
		findings.add(path, "unsupported contract inventory version");
	}
	if inventory.policy != Path::new(POLICY) || !root.join(POLICY).is_file() {
		findings.add(path, "missing or invalid contract policy path");
	}

	let mut missing = BTreeSet::from(["local-owner-seed", "rust-library-apis"]);
	missing.extend(PLANNED.iter().map(|(id, _)| *id));
	missing.extend(markers::BINDINGS.iter().map(|binding| binding.id));

	let mut seen = BTreeSet::new();
	for contract in &inventory.contract {
		let id = contract.id.as_str();
		if !seen.insert(id) {
			findings.add(path, format_args!("{id}: duplicate contract"));
			continue;
		}
		if !missing.remove(id) {
			findings.add(path, format_args!("{id}: unknown contract"));
			continue;
		}
		if let Err(error) = check_record(root, contract) {
			findings.add(path, format_args!("{id}: {error}"));
		}
	}
	for id in missing {
		findings.add(path, format_args!("{id}: missing contract"));
	}
}

fn check_record(root: &Path, record: &Contract) -> Result<(), String> {
	if record
		.notes
		.as_ref()
		.is_some_and(|notes| notes.trim().is_empty())
	{
		return Err("empty contract notes".into());
	}
	if let Some(binding) = markers::BINDINGS
		.iter()
		.find(|binding| binding.id == record.id)
	{
		return binding.check(root, record);
	}
	let (kind, status, owner) = match record.id.as_str() {
		"local-owner-seed" => (
			Kind::LocalProfile,
			Status::DevelopmentUnversioned,
			Some(Path::new("crates/clients/cli/src/profile.rs")),
		),
		"rust-library-apis" => (
			Kind::LibraryApi,
			Status::Development,
			Some(Path::new("Cargo.toml")),
		),
		id => {
			let kind = PLANNED
				.iter()
				.find_map(|(expected, kind)| (*expected == id).then_some(*kind))
				.ok_or("unknown contract")?;
			(kind, Status::Planned, None)
		}
	};
	record.check_classification(kind, status, owner)?;
	if record.version.is_some() || record.required_features.is_some() || record.magic.is_some() {
		return Err("unversioned or unavailable contract has implementation markers".into());
	}
	if let Some(owner) = owner
		&& !root.join(owner).is_file()
	{
		return Err(format!("{} is missing", owner.display()));
	}
	Ok(())
}

impl Contract {
	fn check_classification(
		&self,
		kind: Kind,
		status: Status,
		owner: Option<&Path>,
	) -> Result<(), String> {
		if (self.kind, self.status) != (kind, status) {
			return Err(format!("expected kind {kind:?} and status {status:?}"));
		}
		if self.owner.as_deref() != owner {
			return Err(format!("expected owner {owner:?}"));
		}
		Ok(())
	}
}
