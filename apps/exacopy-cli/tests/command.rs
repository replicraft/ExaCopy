//! Process-level tests for the ExaCopy dispatcher.

use std::process::Command;

fn exacopy() -> Command {
	Command::new(env!("CARGO_BIN_EXE_exacopy"))
}

fn help(args: &[&str]) -> String {
	let output = exacopy().args(args).output().expect("invoke help");
	assert_eq!(output.status.code(), Some(0), "{args:?}");
	assert!(output.stderr.is_empty(), "{args:?}");
	String::from_utf8(output.stdout).expect("read help as UTF-8")
}

#[test]
fn generated_help_describes_the_existing_command_tree() {
	let root = help(&["--help"]);
	for name in ["diff", "copy", "recover", "profile"] {
		assert!(root.contains(name));
	}
	let diff = help(&["diff", "--help"]);
	assert!(diff.contains("Usage: exacopy diff"));
	assert!(diff.contains("--format"));
	assert!(diff.contains("human") && diff.contains("json"));
	assert!(diff.contains("--workers <N>"));
	assert!(diff.contains("--managed-macos"));
	assert!(diff.contains("--local-ntfs"));
	assert!(diff.contains("owner-private, materialized local APFS roots outside File Provider"));
	assert!(diff.contains("protected ancestors"));
	assert!(diff.contains("Outside actors must hold no access handles"));
	let copy = help(&["copy", "--help"]);
	assert!(copy.contains("--profile <DIR>"));
	for action in ["retry", "resume"] {
		let recovery = help(&["recover", action, "--help"]);
		assert!(recovery.contains(&format!("Usage: exacopy recover {action}")));
		assert!(recovery.contains("--source-root <DIR>"));
		assert!(recovery.contains("--profile <DIR>"));
	}
	for action in ["inspect", "finish"] {
		assert!(!help(&["recover", action, "--help"]).contains("--source-root"));
	}
	let profile = help(&["profile", "init", "-h"]);
	assert!(profile.contains("Usage: exacopy profile init"));
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
		&[
			"diff",
			"left",
			"right",
			"--managed-macos",
			"--managed-macos",
		],
		&["diff", "left", "right", "--managed-macos", "--local-ntfs"],
		&["copy", "left", "right"],
		&[
			"copy",
			"left",
			"right",
			"--profile",
			"profile",
			"--managed-macos",
		],
	] {
		let output = exacopy()
			.args(args)
			.output()
			.expect("invoke invalid command");
		assert_eq!(output.status.code(), Some(2), "{args:?}");
		assert!(output.stdout.is_empty(), "{args:?}");
		assert!(!output.stderr.is_empty(), "{args:?}");
	}
}

#[test]
fn diff_worker_ceiling_requires_one_positive_supported_count() {
	for (options, diagnostic) in [
		(
			&["--workers"][..],
			"--workers requires an integer from 1 to 16",
		),
		(
			&["--workers", "--format", "json"],
			"--workers requires an integer from 1 to 16",
		),
		(
			&["--workers", "0"],
			"--workers requires an integer from 1 to 16",
		),
		(
			&["--workers", "-1"],
			"--workers requires an integer from 1 to 16",
		),
		(
			&["--workers", "1.5"],
			"--workers requires an integer from 1 to 16",
		),
		(
			&["--workers", "17"],
			"--workers requires an integer from 1 to 16",
		),
		(
			&["--workers", "99999999999999999999999999"],
			"--workers requires an integer from 1 to 16",
		),
		(&["--workers", "1", "--workers", "4"], "more than once"),
	] {
		let output = exacopy()
			.args(["diff", "absent-left", "absent-right", "--format", "json"])
			.args(options)
			.output()
			.expect("invoke diff with invalid worker option");
		assert_eq!(output.status.code(), Some(2));
		assert!(output.stdout.is_empty());
		let stderr = String::from_utf8(output.stderr).expect("read usage");
		assert!(stderr.contains(diagnostic), "{options:?}: {stderr}");
		assert!(stderr.contains("Usage:"));
	}

	let copy = exacopy()
		.args([
			"copy",
			"absent-source",
			"absent-target",
			"--profile",
			"profile",
			"--workers",
			"4",
		])
		.output()
		.expect("invoke copy with a diff-only option");
	assert_eq!(copy.status.code(), Some(2));
	assert!(copy.stdout.is_empty());
	assert!(String::from_utf8_lossy(&copy.stderr).contains("unexpected argument or option"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_returns_structured_inconclusive_result() {
	let output = exacopy()
		.args([
			"diff",
			"left",
			"right",
			"--format",
			"json",
			"--workers",
			"4",
		])
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

#[cfg(not(target_os = "macos"))]
#[test]
fn managed_macos_opt_in_refuses_other_platforms_without_opening_inputs() {
	let output = exacopy()
		.args([
			"diff",
			"unavailable-left",
			"unavailable-right",
			"--managed-macos",
			"--format",
			"json",
		])
		.output()
		.expect("invoke managed diff on unsupported platform");
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stderr.is_empty());
	let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("read report");
	assert_eq!(report["result"], "inconclusive");
	assert_eq!(report["complete"], false);
	assert_eq!(report["error"]["code"], "E_UNSUPPORTED_PLATFORM");
	assert!(report.get("consistency").is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn managed_macos_opt_in_routes_to_managed_admission() {
	let output = exacopy()
		.args(["diff", "./", "right", "--managed-macos", "--format", "json"])
		.output()
		.expect("invoke managed diff with invalid terminal name");
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stderr.is_empty());
	let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("read report");
	assert_eq!(report["result"], "inconclusive");
	assert_eq!(report["complete"], false);
	assert_eq!(report["error"]["code"], "E_INVALID_PATH");
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

#[cfg(not(target_os = "linux"))]
#[test]
fn retained_copy_inspection_refuses_unsupported_platform_with_no_evidence() {
	let output = exacopy()
		.args([
			"recover",
			"inspect",
			"absent-job",
			"--profile",
			"absent-profile",
			"--format",
			"json",
		])
		.output()
		.expect("invoke retained copy inspection on an unsupported platform");
	assert_eq!(output.status.code(), Some(6));
	assert!(output.stderr.is_empty());
	let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("read report");
	assert_eq!(
		report,
		serde_json::json!({
			"schema": "exacopy.local_recovery_inspection",
			"schema_version": "1.0",
			"result": "failed",
			"code": "E_UNSUPPORTED",
			"message": "local recovery requires Linux"
		})
	);
}

#[test]
fn public_stage_inspection_dispatch_refuses_without_a_valid_owner_key() {
	const SELECTOR: &str = "inspect-public-stage";
	let enabled = cfg!(all(
		target_os = "linux",
		feature = "experimental-linux-public-apply"
	));
	assert_eq!(help(&["recover", "--help"]).contains(SELECTOR), enabled);

	let weak_key = "00".repeat(32);
	let output = exacopy()
		.args([
			"recover",
			SELECTOR,
			"absent-job",
			"--owner-key",
			&weak_key,
			"--format",
			"json",
		])
		.output()
		.expect("invoke public-stage inspection with a weak public key");
	if enabled {
		assert_eq!(output.status.code(), Some(8));
		assert!(output.stderr.is_empty());
		let report: serde_json::Value =
			serde_json::from_slice(&output.stdout).expect("read report");
		assert_eq!(
			report,
			serde_json::json!({
				"schema": "exacopy.public_stage_inspection",
				"schema_version": "1.0",
				"authority": "none",
				"status": "refused",
				"reason": "owner_key_refused"
			})
		);
	} else {
		assert_eq!(output.status.code(), Some(2));
		assert!(output.stdout.is_empty());
		let stderr = String::from_utf8(output.stderr).expect("read usage");
		assert!(stderr.contains("Usage:"));
		assert!(!stderr.contains("absent-job"));
		assert!(!stderr.contains(&weak_key));
	}
}

#[test]
fn retry_requires_one_explicit_source_root_and_profile() {
	for (options, error) in [
		(&["--profile", "profile"][..], "--source-root <DIR>"),
		(
			&["--profile", "profile", "--source-root"],
			"--source-root <DIR>",
		),
		(
			&["--source-root", "--format", "json"],
			"--source-root <DIR>",
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
			"more than once",
		),
		(&["--source-root", "source"], "--profile <DIR>"),
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
fn resume_requires_one_explicit_source_root_and_profile() {
	for (options, error) in [
		(&["--profile", "profile"][..], "--source-root <DIR>"),
		(&["--source-root", "source"], "--profile <DIR>"),
		(
			&["--source-root", "--profile", "profile"],
			"--source-root <DIR>",
		),
		(
			&["--source-root", "source", "--profile", "--format"],
			"--profile <DIR>",
		),
		(
			&[
				"--profile",
				"profile",
				"--source-root",
				"one",
				"--source-root",
				"two",
			],
			"more than once",
		),
		(
			&[
				"--source-root",
				"source",
				"--profile",
				"one",
				"--profile",
				"two",
			],
			"more than once",
		),
	] {
		let output = exacopy()
			.args(["recover", "resume", "job"])
			.args(options)
			.output()
			.expect("invoke invalid resume command");
		assert_eq!(output.status.code(), Some(2));
		assert!(output.stdout.is_empty());
		let stderr = String::from_utf8_lossy(&output.stderr);
		assert!(stderr.contains(error), "{options:?}: {stderr}");
	}
}

#[test]
fn source_root_option_requires_source_based_recovery() {
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
			.expect("invoke recovery command with a source-only option");
		assert_eq!(output.status.code(), Some(2));
		assert!(output.stdout.is_empty());
		assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected argument or option"));
	}
}

#[cfg(not(target_os = "linux"))]
#[test]
fn source_based_recovery_refuses_unsupported_platform_without_accessing_inputs() {
	for action in ["retry", "resume"] {
		let output = exacopy()
			.args([
				"recover",
				action,
				"job",
				"--source-root",
				"absent-source-root",
				"--profile",
				"absent-profile",
				"--format",
				"json",
			])
			.output()
			.expect("invoke recovery on unsupported platform");
		assert_eq!(output.status.code(), Some(6));
		assert!(output.stderr.is_empty());
		let report: serde_json::Value =
			serde_json::from_slice(&output.stdout).expect("read report");
		assert_eq!(report["result"], "failed");
		assert_eq!(report["code"], "E_UNSUPPORTED");
	}
}

#[test]
fn invalid_parse_keeps_raw_input_out_of_diagnostics() {
	let secret = "diagnostic-marker-pretending-to-be-a-private-path";
	let output = exacopy()
		.args([
			"recover",
			"resume",
			"job",
			"--profile",
			secret,
			"--",
			secret,
		])
		.output()
		.expect("invoke malformed resume command");
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(stderr.contains("Usage:"));
	assert!(!stderr.contains(secret));
}
