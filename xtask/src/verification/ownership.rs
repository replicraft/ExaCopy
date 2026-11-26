use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{Gate, artifact_text};
use crate::finding::Findings;

const INVENTORY: &str = "specs/verification/owners.toml";
const OWNER_INDEX: &str = "docs/verification.md";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
	schema_version: u32,
	pub(super) owners: BTreeMap<String, Vec<Gate>>,
	#[serde(default)]
	pub(super) native_fixtures: BTreeMap<String, Vec<PathBuf>>,
}

impl Inventory {
	pub(super) fn load(root: &Path, findings: &mut Findings) -> Option<Self> {
		artifact_text(root, Path::new(OWNER_INDEX), findings);
		let contents = artifact_text(root, Path::new(INVENTORY), findings)?;
		let inventory = match toml::from_str::<Self>(&contents) {
			Ok(inventory) => inventory,
			Err(error) => {
				findings.add(&root.join(INVENTORY), error);
				return None;
			}
		};
		let path = root.join(INVENTORY);
		if inventory.schema_version != 1
			|| (inventory.owners.is_empty() && inventory.native_fixtures.is_empty())
		{
			findings.add(
				&path,
				"expected schema_version 1 and at least one verification owner",
			);
		}
		for (owner, gates) in &inventory.owners {
			if gates.is_empty() || gates.iter().collect::<BTreeSet<_>>().len() != gates.len() {
				findings.add(
					&path,
					format_args!("{owner} must list unique, nonempty minimum gate kinds"),
				);
			}
		}
		for (owner, manifests) in &inventory.native_fixtures {
			if manifests.is_empty()
				|| manifests.iter().collect::<BTreeSet<_>>().len() != manifests.len()
			{
				findings.add(
					&path,
					format_args!("{owner} must list unique, nonempty native fixture manifests"),
				);
			}
		}
		Some(inventory)
	}
}

#[cfg(test)]
mod tests;
