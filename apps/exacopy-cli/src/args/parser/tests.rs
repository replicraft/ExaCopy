use std::ffi::OsString;
use std::path::Path;

use super::{Command, Format, parse};

fn from_args(args: &[&str]) -> Result<Command, String> {
	parse(args.iter().map(OsString::from))
}

#[cfg(unix)]
#[test]
fn new_commands_keep_raw_input_and_baseline_paths() {
	use std::os::unix::ffi::OsStringExt as _;

	let source = OsString::from_vec(b"-raw-source\xff".to_vec());
	let baseline = OsString::from_vec(b"-raw-baseline\xfe".to_vec());
	let create = parse(
		["manifest", "create", "--"]
			.map(OsString::from)
			.into_iter()
			.chain([source.clone()]),
	)
	.expect("parse manifest creation");
	let Command::ManifestCreate { path } = create else {
		panic!("expected manifest creation");
	};
	assert_eq!(path.as_os_str(), source);

	let verify = parse(
		["verify", "--"]
			.map(OsString::from)
			.into_iter()
			.chain([source.clone(), "--manifest".into(), baseline.clone()])
			.chain(["--format", "json"].map(OsString::from)),
	)
	.expect("parse verification");
	let Command::Verify(verify) = verify else {
		panic!("expected verification");
	};
	assert_eq!(verify.path.as_os_str(), source);
	assert_eq!(verify.manifest.as_os_str(), baseline);
	assert!(matches!(verify.format, Format::Json));
}

#[test]
fn verification_defaults_to_human_and_defers_invalid_path_values() {
	let verify = from_args(&["verify", "", "--manifest", "baseline"]).expect("parse verification");
	let Command::Verify(verify) = verify else {
		panic!("expected verification");
	};
	assert_eq!(verify.path, Path::new(""));
	assert_eq!(verify.manifest, Path::new("baseline"));
	assert!(matches!(verify.format, Format::Human));
}

#[test]
fn invalid_manifest_cli_syntax_never_returns_a_command() {
	for args in [
		&["verify", "path"][..],
		&["verify", "path", "--manifest"],
		&["verify", "path", "--manifest", "--format", "json"],
		&[
			"verify",
			"path",
			"--manifest",
			"first",
			"--manifest",
			"second",
		],
		&[
			"verify",
			"path",
			"--manifest",
			"baseline",
			"--format",
			"hex",
		],
		&[
			"verify",
			"path",
			"--manifest",
			"baseline",
			"--source-root",
			"root",
		],
		&["manifest", "create"],
		&["manifest", "create", "path", "--format", "json"],
		&["manifest", "compare", "path"],
	] {
		let Err(diagnostic) = from_args(args) else {
			panic!("invalid input parsed successfully: {args:?}");
		};
		assert!(diagnostic.contains("Usage:"), "{args:?}: {diagnostic}");
	}
}

#[test]
fn help_reports_explicit_verification_baseline_and_creation_output() {
	let Command::Help(verify) =
		from_args(&["verify", "--help"]).expect("generate verification help")
	else {
		panic!("expected verification help");
	};
	assert!(verify.contains("--manifest <FILE>"));
	assert!(verify.contains("--format"));

	let Command::Help(create) =
		from_args(&["manifest", "create", "--help"]).expect("generate creation help")
	else {
		panic!("expected creation help");
	};
	assert!(create.contains("Usage: exacopy manifest create"));
	assert!(create.contains("JSON"));
	assert!(!create.contains("--format"));
}

#[test]
fn plan_accepts_one_explicit_profile_and_output_and_refuses_unknown_policy() {
	let command = parse(
		[
			"plan",
			"source",
			"target",
			"--profile",
			"owner",
			"--output",
			"bundle/plan.json",
		]
		.into_iter()
		.map(OsString::from),
	)
	.ok()
	.unwrap();
	let Command::Plan(plan) = command else {
		panic!("expected the typed plan command")
	};
	assert_eq!(plan.source, std::path::Path::new("source"));
	assert_eq!(plan.destination, std::path::Path::new("target"));
	assert_eq!(plan.profile, std::path::Path::new("owner"));
	assert_eq!(plan.output, std::path::Path::new("bundle/plan.json"));

	for args in [
		&["plan", "source", "target", "--profile", "owner"][..],
		&["plan", "source", "target", "--output", "out.json"],
		&[
			"plan",
			"source",
			"target",
			"--profile",
			"--overwrite",
			"--output",
			"out.json",
		],
		&[
			"plan",
			"source",
			"target",
			"--profile",
			"owner",
			"--output",
			"out.json",
			"--overwrite",
		],
		&[
			"plan",
			"source",
			"target",
			"--profile",
			"owner",
			"--output",
			"out.json",
			"--output",
			"other.json",
		],
	] {
		assert!(parse(args.iter().copied().map(OsString::from)).is_err());
	}
}

#[test]
fn public_stage_command_availability_follows_its_exact_feature() {
	let Ok(Command::Help(help)) = from_args(&["recover", "--help"]) else {
		panic!("expected recovery help");
	};
	let enabled = cfg!(all(
		target_os = "linux",
		feature = "experimental-linux-public-apply"
	));
	assert_eq!(help.contains("inspect-public-stage"), enabled);
	let key = "01".repeat(32);
	let selected = from_args(&[
		"recover",
		"inspect-public-stage",
		"job",
		"--owner-key",
		&key,
	]);
	assert_eq!(selected.is_ok(), enabled);
}

#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
#[test]
fn public_stage_selection_keeps_owner_key_separate_from_legacy_recovery() {
	let key = "ab".repeat(32);
	let args = [
		"recover",
		"inspect-public-stage",
		"job",
		"--owner-key",
		&key,
		"--format",
		"json",
	];
	let Ok(Command::InspectPublicStage(command)) = from_args(&args) else {
		panic!("expected explicit public-stage command");
	};
	assert_eq!(command.owner_key, [0xab; 32]);
	assert_eq!(command.job, Path::new("job"));
	assert!(matches!(command.format, Format::Json));

	for extra in [["--profile", "private"], ["--source-root", "source"]] {
		let with_extra: Vec<_> = args.into_iter().chain(extra).collect();
		assert!(from_args(&with_extra).is_err(), "{extra:?}");
	}
	assert!(from_args(&args[..3]).is_err());
	for invalid in [
		"a".repeat(63),
		"a".repeat(65),
		"AB".repeat(32),
		"g0".repeat(32),
	] {
		let mut args = args;
		args[4] = &invalid;
		assert!(from_args(&args).is_err(), "{invalid:?}");
	}
	assert!(from_args(&["recover", "inspect", "job", "--owner-key", &key]).is_err());
	assert!(matches!(
		from_args(&["recover", "inspect", "job", "--profile", "private"]),
		Ok(Command::Recover(_))
	));
}
