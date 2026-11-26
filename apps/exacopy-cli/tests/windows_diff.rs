//! Process-level coverage of the opt-in Windows comparison profile.

use std::process::Command;

use serde_json::Value;

fn exacopy() -> Command {
	let executable = env!("CARGO_BIN_EXE_exacopy");
	#[cfg(all(target_os = "windows", feature = "experimental-windows-diff"))]
	if let Some(qualified) = std::env::var_os("EXACOPY_WINDOWS_QUALIFIED_CLI") {
		assert_eq!(
			std::fs::canonicalize(executable).expect("resolve Cargo's CLI executable"),
			std::fs::canonicalize(qualified).expect("resolve the qualified CLI executable"),
			"the CLI integration test must execute the selected Cargo artifact"
		);
	}
	Command::new(executable)
}

#[test]
fn ntfs_profile_refuses_unavailable_or_unadmitted_input() {
	let output = exacopy()
		.args([
			"diff",
			"relative",
			"right",
			"--local-ntfs",
			"--format",
			"json",
		])
		.output()
		.expect("invoke the NTFS profile with an invalid operand");
	assert_eq!(output.status.code(), Some(2));
	let report: Value = serde_json::from_slice(&output.stdout).expect("read the JSON refusal");
	assert_eq!(report["result"], "inconclusive");
	assert_eq!(report["complete"], false);
	assert!(report.get("consistency").is_none());
	let code = if cfg!(all(
		target_os = "windows",
		feature = "experimental-windows-diff"
	)) {
		"E_INVALID_PATH"
	} else {
		"E_UNSUPPORTED_PLATFORM"
	};
	assert_eq!(report["error"]["code"], code);
}

#[cfg(all(target_os = "windows", feature = "experimental-windows-diff"))]
#[path = "windows_diff/native.rs"]
mod native;
