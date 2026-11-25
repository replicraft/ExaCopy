//! Process-level tests for the ExaCopy dispatcher.

use std::process::Command;

fn exacopy() -> Command {
	Command::new(env!("CARGO_BIN_EXE_exacopy"))
}

#[test]
fn help_describes_diff_and_exits_successfully() {
	let output = exacopy().arg("--help").output().expect("invoke help");
	assert_eq!(output.status.code(), Some(0));
	assert!(output.stderr.is_empty());
	let usage = String::from_utf8(output.stdout).expect("read help as UTF-8");
	assert!(usage.contains("exacopy diff"));
	assert!(usage.contains("--format human|json"));
}

#[test]
fn rejects_missing_operands_and_unsupported_or_repeated_options() {
	for args in [
		&["diff", "left"][..],
		&["diff", "left", "right", "--compare", "hash"],
		&["diff", "left", "right", "--format"],
		&[
			"diff", "left", "right", "--format", "json", "--format", "human",
		],
		&["copy", "left", "right"],
	] {
		let output = exacopy()
			.args(args)
			.output()
			.expect("invoke invalid command");
		assert_eq!(output.status.code(), Some(2));
		assert!(output.stdout.is_empty());
		assert!(!output.stderr.is_empty());
	}
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_returns_structured_inconclusive_result() {
	let output = exacopy()
		.args(["diff", "left", "right", "--format", "json"])
		.output()
		.expect("invoke diff on unsupported platform");
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stderr.is_empty());
	let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("read report");
	assert_eq!(report["result"], "inconclusive");
	assert_eq!(report["complete"], false);
	assert_eq!(report["error"]["code"], "E_UNSUPPORTED_PLATFORM");
	assert!(report.get("consistency").is_none());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn copy_refuses_unsupported_platform_without_accessing_inputs() {
	let output = exacopy()
		.args([
			"copy",
			"source",
			"target",
			"--profile",
			"profile",
			"--format",
			"json",
		])
		.output()
		.expect("invoke copy on unsupported platform");
	assert_eq!(output.status.code(), Some(6));
	assert!(output.stderr.is_empty());
	let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("read report");
	assert_eq!(report["publication"], "not_published");
	assert_eq!(report["error"]["code"], "E_UNSUPPORTED");
}
