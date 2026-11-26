use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use super::*;
use crate::args::{Format, parse};

const GRANTS: [&str; 10] = [
	"--profile",
	"/owner/private",
	"--ssh-profile",
	"/ssh/private",
	"--destination-qualification",
	"/destination/attestation",
	"--qualification-trust",
	"/trust/private",
	"--metadata",
	"sftp-data-only-v1",
];

fn args(operands: &[&str]) -> impl Iterator<Item = OsString> {
	operands.iter().chain(&GRANTS).map(OsString::from)
}

#[test]
fn get_preserves_raw_absolute_ssh_and_native_operand_bytes() {
	let source = OsString::from_vec(b"operator@host:/nested/raw-\xff".to_vec());
	let target = OsString::from_vec(b"-local-\xfe".to_vec());
	let Parsed {
		request,
		options:
			RemoteOptions {
				profile,
				ssh_profile,
				destination_qualification,
				qualification_trust,
				metadata,
				format,
			},
	} = remote(
		["get".into(), source.clone(), target.clone()]
			.into_iter()
			.chain(GRANTS.map(OsString::from))
			.chain(["--format".into(), "json".into()]),
	);
	let RemoteRequest::Get {
		source: parsed_source,
		target: parsed_target,
	} = request
	else {
		panic!("expected get");
	};
	assert_eq!(parsed_source, source);
	assert_eq!(parsed_target, PathBuf::from(target));
	assert_eq!(profile, PathBuf::from(GRANTS[1]));
	assert_eq!(ssh_profile, PathBuf::from(GRANTS[3]));
	assert_eq!(destination_qualification, PathBuf::from(GRANTS[5]));
	assert_eq!(qualification_trust, PathBuf::from(GRANTS[7]));
	assert!(matches!(metadata, RemoteMetadata::SftpDataOnlyV1));
	assert!(matches!(format, Format::Json));
}

#[test]
fn resume_uses_only_retained_job_and_explicit_grants() {
	let remote = remote(args(&["recover", "remote-resume", "--", "-job"]));
	let RemoteRequest::Resume { job } = remote.request else {
		panic!("expected remote resume");
	};
	assert_eq!(job, PathBuf::from("-job"));
	assert!(matches!(remote.options.format, Format::Human));
	for option in ["--source-root", "--source", "--target"] {
		let parsed = parse(
			args(&["recover", "remote-resume", "job"]).chain([option.into(), "other".into()]),
		);
		assert!(parsed.is_err(), "accepted an override for {option}");
	}
}

#[test]
fn both_commands_require_every_explicit_grant_and_never_echo_input_paths() {
	for invocation in [
		vec!["get", "secret-source", "secret-target"],
		vec!["recover", "remote-resume", "secret-job"],
	] {
		for omitted in 0..GRANTS.len() {
			let args = invocation
				.iter()
				.copied()
				.chain(
					GRANTS
						.iter()
						.enumerate()
						.filter_map(|(index, grant)| (index / 2 != omitted / 2).then_some(*grant)),
				)
				.map(OsString::from);
			let Err(error) = parse(args) else {
				panic!("accepted omission of {}", GRANTS[omitted & !1]);
			};
			assert!(
				!error.contains("secret-"),
				"raw input leaked into diagnostic"
			);
		}
	}
}

#[test]
fn refuses_duplicate_and_unknown_metadata_and_missing_owner_value() {
	let mut input: Vec<_> = args(&["get", "user@host:file", "target"]).collect();
	input[3 + GRANTS.len() - 1] = "required-data".into();
	assert!(parse(input.into_iter()).is_err());
	let duplicate = args(&["get", "user@host:file", "target"])
		.chain(["--metadata".into(), "sftp-data-only-v1".into()]);
	assert!(parse(duplicate).is_err());
	let missing = ["get", "user@host:file", "target", "--profile"]
		.into_iter()
		.chain(GRANTS[2..].iter().copied())
		.map(OsString::from);
	assert!(parse(missing).is_err());
}

type Parsed = RemoteCommand;

fn remote(args: impl Iterator<Item = OsString>) -> Parsed {
	let Command::Remote(command) = parse(args).expect("remote invocation") else {
		panic!("expected a remote command");
	};
	command
}
