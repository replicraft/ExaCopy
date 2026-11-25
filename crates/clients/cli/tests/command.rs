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
	assert!(usage.contains("exacopy recover retry [--] JOB --source-root DIR"));
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

#[test]
fn retry_requires_one_explicit_source_root_and_profile() {
	for (options, error) in [
		(
			&["--profile", "profile"][..],
			"requires an explicit --source-root DIR",
		),
		(
			&["--profile", "profile", "--source-root"],
			"--source-root requires a directory",
		),
		(
			&["--source-root", "--format", "json"],
			"--source-root requires a directory",
		),
		(
			&[
				"--source-root",
				"one",
				"--source-root",
				"two",
				"--profile",
				"profile",
			],
			"repeated recovery option",
		),
		(
			&["--source-root", "source"],
			"requires an explicit --profile DIR",
		),
	] {
		let output = exacopy()
			.args(["recover", "retry", "job"])
			.args(options)
			.output()
			.expect("invoke invalid retry command");
		assert_eq!(output.status.code(), Some(2));
		assert!(output.stdout.is_empty());
		assert!(String::from_utf8_lossy(&output.stderr).contains(error));
	}
}

#[test]
fn source_root_option_is_restricted_to_retry() {
	for action in ["inspect", "finish"] {
		let output = exacopy()
			.args([
				"recover",
				action,
				"job",
				"--profile",
				"profile",
				"--source-root",
				"source",
			])
			.output()
			.expect("invoke recovery command with a retry-only option");
		assert_eq!(output.status.code(), Some(2));
		assert!(output.stdout.is_empty());
		assert!(
			String::from_utf8_lossy(&output.stderr)
				.contains("--source-root requires recover retry")
		);
	}
}

#[cfg(not(target_os = "linux"))]
#[test]
fn retry_refuses_unsupported_platform_without_accessing_inputs() {
	let output = exacopy()
		.args([
			"recover",
			"retry",
			"job",
			"--source-root",
			"absent-source-root",
			"--profile",
			"absent-profile",
			"--format",
			"json",
		])
		.output()
		.expect("invoke retry on unsupported platform");
	assert_eq!(output.status.code(), Some(6));
	assert!(output.stderr.is_empty());
	let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("read report");
	assert_eq!(report["result"], "failed");
	assert_eq!(report["code"], "E_UNSUPPORTED");
}
