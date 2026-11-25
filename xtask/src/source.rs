use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use syn::visit::Visit;

use crate::finding::Findings;

mod entrypoint;
mod syntax;

const MAX_PHYSICAL_LINES: usize = 500;
const RUST_EXTENSION: &str = "rs";

/// Collects repository files, leaving explicitly local architecture and build output alone.
/// Symlinks are included as entries, but are never traversed.
pub(crate) fn files(root: &Path, findings: &mut Findings) -> Vec<PathBuf> {
	let mut files = Vec::new();
	collect(root, root, &mut files, findings);
	files.sort_unstable();
	files
}

fn collect(root: &Path, directory: &Path, files: &mut Vec<PathBuf>, findings: &mut Findings) {
	let entries = match fs::read_dir(directory) {
		Ok(entries) => entries,
		Err(error) => {
			findings.add(directory, error);
			return;
		}
	};
	for entry in entries {
		let entry = match entry {
			Ok(entry) => entry,
			Err(error) => {
				findings.add(directory, error);
				continue;
			}
		};
		let path = entry.path();
		let name = entry.file_name();
		if name == ".git" || path == root.join("docs/temp") {
			continue;
		}
		match entry.file_type() {
			Ok(kind) if kind.is_dir() => {
				let lake_cache = name == ".lake"
					&& directory
						.file_name()
						.is_some_and(|parent| parent == "verification");
				if path != root.join("target") && !lake_cache {
					collect(root, &path, files, findings);
				}
			}
			Ok(_) => files.push(path),
			Err(error) => findings.add(&path, error),
		}
	}
}

pub(crate) fn check(path: &Path, findings: &mut Findings) {
	if path.extension() != Some(OsStr::new(RUST_EXTENSION)) {
		return;
	}
	if path.is_symlink() {
		findings.add(
			path,
			"authored Rust must be a regular file in the workspace",
		);
		return;
	}
	match fs::read_to_string(path) {
		Ok(source) => check_text(path, &source, findings),
		Err(error) => findings.add(path, error),
	}
}

fn check_text(path: &Path, source: &str, findings: &mut Findings) {
	let line_count = source.lines().count();
	if line_count > MAX_PHYSICAL_LINES {
		findings.add(
			path,
			format_args!(
				"{line_count} physical lines exceed the {MAX_PHYSICAL_LINES}-line ceiling"
			),
		);
	}
	let file = match syn::parse_file(source) {
		Ok(file) => file,
		Err(error) => {
			findings.at_line(
				path,
				error.span().start().line,
				format_args!("invalid Rust: {error}"),
			);
			return;
		}
	};
	match path.file_name().and_then(OsStr::to_str) {
		Some("lib.rs" | "mod.rs") => entrypoint::check_declarations(path, &file, findings),
		Some("main.rs") => entrypoint::check_main(path, &file, findings),
		_ => (),
	}
	syntax::SourcePolicy::new(path, findings).visit_file(&file);
}

#[cfg(test)]
mod tests;
