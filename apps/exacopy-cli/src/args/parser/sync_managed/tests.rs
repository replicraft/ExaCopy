use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

use super::*;
use crate::args::{Command, parse};

const KEY: &str = "abababababababababababababababababababababababababababababababab";
const ID: &str = "01010101010101010101010101010101";
const DIGEST: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const PREVIEW_ARGS: [&str; 9] = [
	NAME,
	PREVIEW,
	"--profile",
	"/selected/profile",
	"--owner-key",
	KEY,
	"--selection",
	ID,
	"--receipt-stdin",
];
const INIT_ARGS: [&str; 17] = [
	NAME,
	INIT,
	"--profile",
	"/selected/profile",
	"--owner-key",
	KEY,
	"--selection",
	ID,
	"--profile-device",
	"0",
	"--profile-inode",
	"8",
	"--revision",
	"2",
	"--approve-request",
	DIGEST,
	"--request-stdin",
];

fn from_args(args: &[&str]) -> Result<Command, String> {
	parse(args.iter().map(OsString::from))
}

#[test]
fn parses_exact_typed_initialization_and_preserves_raw_profile_path() {
	let mut args = INIT_ARGS.map(OsString::from);
	let raw_path = OsString::from_vec(b"/selected/profile\xff".to_vec());
	args[3] = raw_path.clone();
	let Command::SyncManaged(SyncManagedCommand::Init(args)) = parse(args.into_iter()).unwrap()
	else {
		panic!("expected managed initialization");
	};
	assert_eq!(args.profile.as_os_str(), raw_path);
	assert_eq!(args.profile_device, 0);
	assert_eq!(args.profile_inode.get(), 8);
	assert_eq!(args.owner_key, [0xab; 32]);
	assert_eq!(args.selection, [1; 16]);
	assert_eq!(args.revision.get(), 2);
	assert_eq!(args.approve_request, [0xcd; 32]);
}

#[test]
fn parses_preview_with_independent_owner_and_selection() {
	let Command::SyncManaged(SyncManagedCommand::Preview {
		profile,
		owner_key,
		selection,
	}) = from_args(&PREVIEW_ARGS).unwrap()
	else {
		panic!("expected managed preview");
	};
	assert_eq!(profile.to_str(), Some("/selected/profile"));
	assert_eq!(owner_key, [0xab; 32]);
	assert_eq!(selection, [1; 16]);
}

#[test]
fn refuses_missing_duplicate_abbreviated_or_cross_operation_options() {
	for args in [INIT_ARGS.as_slice(), PREVIEW_ARGS.as_slice()] {
		assert!(from_args(&args[..args.len() - 1]).is_err());
		for index in (2..args.len() - 1).step_by(2) {
			let mut without = args.to_vec();
			without.drain(index..index + 2);
			assert!(from_args(&without).is_err());
			let mut duplicate = args.to_vec();
			duplicate.extend_from_slice(&args[index..index + 2]);
			assert!(from_args(&duplicate).is_err());
		}
		let mut duplicate_stdin = args.to_vec();
		duplicate_stdin.push(args[args.len() - 1]);
		assert!(from_args(&duplicate_stdin).is_err());
	}
	let mut preview = PREVIEW_ARGS;
	for option in ["--request-stdin", "--receipt", "--receipt-stdin=true"] {
		preview[8] = option;
		assert!(from_args(&preview).is_err());
	}
	assert!(from_args(&[NAME, "pre"]).is_err());
	assert!(from_args(&[NAME, "help"]).is_err());
	assert!(from_args(&[NAME]).is_err());
}

#[test]
fn refuses_partial_noncanonical_and_overflow_values() {
	let mut preview = PREVIEW_ARGS;
	for path in [
		"",
		"relative",
		"/",
		"/profile/",
		"//profile",
		"/./profile",
		"/a/../profile",
	] {
		preview[3] = path;
		assert!(from_args(&preview).is_err());
	}
	for (index, bad) in [
		(5, "ab"),
		(
			5,
			"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
		),
		(
			5,
			"abababababababababababababababababababababababababababababababab ",
		),
		(7, "00000000000000000000000000000000"),
		(7, "0101010101010101010101010101010g"),
	] {
		let mut preview = PREVIEW_ARGS;
		preview[index] = bad;
		assert!(from_args(&preview).is_err());
	}
	for (index, invalid) in [
		(9, "01"),
		(9, "+1"),
		(9, "18446744073709551616"),
		(11, "0"),
		(11, "8x"),
		(13, "0"),
		(13, "١"),
		(15, "cd"),
	] {
		let mut init = INIT_ARGS;
		init[index] = invalid;
		assert!(from_args(&init).is_err());
	}
	assert_eq!(decimal(b"18446744073709551615"), Some(u64::MAX));
}

#[test]
fn help_is_scoped_and_legacy_preview_is_independent() {
	for (operation, required, absent) in [
		(INIT, "--request-stdin", "--receipt-stdin"),
		(PREVIEW, "--receipt-stdin", "--request-stdin"),
	] {
		let Command::Help(help) = from_args(&[NAME, operation, "--help"]).unwrap() else {
			panic!("expected scoped help");
		};
		assert!(help.contains(required));
		assert!(help.contains("--selection"));
		assert!(!help.contains(absent));
	}
	let legacy = [
		"sync-preview",
		"/pair",
		"left",
		"right",
		"name",
		"--no-history",
	];
	assert!(matches!(from_args(&legacy), Ok(Command::SyncPreview(_))));
	let mut incorrect = legacy;
	incorrect[5] = "--receipt-stdin";
	assert!(from_args(&incorrect).is_err());
}

#[test]
fn profile_identity_requires_only_a_canonical_raw_profile() {
	let raw_path = OsString::from_vec(b"/selected/profile\xff".to_vec());
	let args = [
		NAME.into(),
		PROFILE_IDENTITY.into(),
		"--profile".into(),
		raw_path.clone(),
	];
	let Command::SyncManaged(SyncManagedCommand::ProfileIdentity { profile }) =
		parse(args.into_iter()).unwrap()
	else {
		panic!("expected managed profile identity");
	};
	assert_eq!(profile.as_os_str(), raw_path);

	assert!(from_args(&[NAME, PROFILE_IDENTITY]).is_err());
	assert!(from_args(&[NAME, "profile-id"]).is_err());
	for bad in [
		"",
		"relative",
		"/",
		"/profile/",
		"//profile",
		"/a/../profile",
	] {
		assert!(from_args(&[NAME, PROFILE_IDENTITY, "--profile", bad]).is_err());
	}

	let args = [NAME, PROFILE_IDENTITY, "--profile", "/selected/profile"];
	for extra in [
		["--profile", "/other"].as_slice(),
		["--owner-key", KEY].as_slice(),
		["--selection", ID].as_slice(),
		["--receipt-stdin"].as_slice(),
		["--request-stdin"].as_slice(),
		["--output", "/result"].as_slice(),
		["--seed", "/seed"].as_slice(),
	] {
		let mut invalid = args.to_vec();
		invalid.extend_from_slice(extra);
		assert!(from_args(&invalid).is_err());
	}

	let Command::Help(help) = from_args(&[NAME, PROFILE_IDENTITY, "--help"]).unwrap() else {
		panic!("expected scoped help");
	};
	assert!(help.contains("--profile"));
	for forbidden in [
		"--owner-key",
		"--selection",
		"--receipt-stdin",
		"--request-stdin",
		"--output",
	] {
		assert!(!help.contains(forbidden));
	}
}
