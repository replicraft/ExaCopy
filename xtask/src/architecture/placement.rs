use std::path::{Component, Path};

use cargo_metadata::{Package, TargetKind};

use crate::finding::Findings;
use crate::source;

const LIBRARY_DOMAINS: &[&str] = &[
	"adapters",
	"engineering",
	"engines",
	"formats",
	"foundation",
	"interfaces",
	"io",
	"net",
	"platform",
	"runtime",
	"security",
	"storage",
];

pub(super) fn check(root: &Path, package: &Package, findings: &mut Findings) {
	let manifest = package.manifest_path.as_std_path();
	let Some(owner) = manifest.parent() else {
		return;
	};
	let name = package.name.as_str();
	let path = owner.strip_prefix(root).unwrap_or(owner);
	let app = path == Path::new("apps").join(name);
	let tooling = name == "xtask" && path == Path::new("xtask");
	let library = LIBRARY_DOMAINS
		.iter()
		.any(|domain| path == Path::new("crates").join(domain).join(name));
	if !tooling && (!name.starts_with("exacopy-") || !(app || library)) {
		findings.add(
			manifest,
			"package must use its fully prefixed name under apps/ or a canonical crates/ domain",
		);
	}

	let mut has_binary = false;
	let canonical_owner = owner.canonicalize().ok();
	for target in &package.targets {
		let path = target.src_path.as_std_path();
		let inside = path.strip_prefix(owner).is_ok_and(|relative| {
			relative
				.components()
				.all(|part| matches!(part, Component::Normal(_)))
		}) && canonical_owner.as_ref().is_some_and(|owner| {
			path.canonicalize()
				.is_ok_and(|source| source.starts_with(owner))
		});
		if !inside {
			findings.add(
				manifest,
				format_args!(
					"target {} source must belong to its package: {}",
					target.name,
					path.display()
				),
			);
			continue;
		}
		if target.kind.contains(&TargetKind::Bin) {
			has_binary = true;
			if !app && !tooling {
				findings.add(
					manifest,
					format_args!("product binary {} must be owned by apps/", target.name),
				);
			} else if path.file_name().is_some_and(|file| file != "main.rs") {
				source::check_binary(path, findings);
			}
		}
	}
	if app && !has_binary {
		findings.add(
			manifest,
			"an application package must own an executable target",
		);
	}
}
