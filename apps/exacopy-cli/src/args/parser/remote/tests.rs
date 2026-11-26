use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

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

#[derive(serde::Deserialize)]
struct CampaignVectors {
	options: CampaignPaths,
	cases: Vec<CampaignCase>,
}

#[derive(serde::Deserialize)]
struct CampaignPaths {
	owner_profile: PathBuf,
	ssh_profile: PathBuf,
	qualification: PathBuf,
	trust: PathBuf,
}

#[derive(serde::Deserialize)]
struct CampaignCase {
	subcommand: Vec<String>,
	operands: Vec<String>,
	qualification_override: Option<PathBuf>,
	argv: Vec<String>,
}

#[test]
fn campaign_vectors_parse_exact_operands_and_grants() {
	let CampaignVectors { options, cases } = serde_json::from_str(include_str!(
		"../../../../verification/remote/campaign-argv.json"
	))
	.expect("campaign argv vectors");
	for case in cases {
		let subcommand_end = case.subcommand.len();
		let operands_end = subcommand_end + 1 + case.operands.len();
		let invalid = case.argv[..subcommand_end]
			.iter()
			.chain(&case.argv[operands_end..])
			.chain(&case.argv[subcommand_end..operands_end])
			.map(OsString::from);
		let Err(error) = parse(invalid) else {
			panic!("accepted options before operands for {:?}", case.subcommand);
		};
		assert!(error.starts_with("exacopy: use -- before a path that starts with a dash\n"));

		let parsed = remote(case.argv.into_iter().map(OsString::from));
		match (parsed.request, case.operands.as_slice()) {
			(RemoteRequest::Get { source, target }, [expected_source, expected_target]) => {
				assert_eq!(source, OsStr::new(expected_source));
				assert_eq!(target, Path::new(expected_target));
			}
			(RemoteRequest::Resume { job }, [expected_job]) => {
				assert_eq!(job, Path::new(expected_job));
			}
			_ => panic!("wrong typed request for {:?}", case.subcommand),
		}
		assert_eq!(parsed.options.profile, options.owner_profile);
		assert_eq!(parsed.options.ssh_profile, options.ssh_profile);
		assert_eq!(parsed.options.qualification_trust, options.trust);
		assert_eq!(
			&parsed.options.destination_qualification,
			case.qualification_override
				.as_ref()
				.unwrap_or(&options.qualification),
		);
		assert!(matches!(parsed.options.format, Format::Json));
		assert!(matches!(
			parsed.options.metadata,
			RemoteMetadata::SftpDataOnlyV1
		));
	}
}

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
