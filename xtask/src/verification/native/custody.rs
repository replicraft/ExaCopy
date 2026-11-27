use std::ffi::OsStr;
use std::path::Path;

use super::{Fixture, artifact_text};
use crate::finding::Findings;

pub(super) fn check(
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
