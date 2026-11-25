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
