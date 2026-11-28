use std::ffi::OsString;

use super::super::{Command, parse};

#[cfg(not(all(target_os = "macos", feature = "experimental-apfs-copy")))]
#[test]
fn inspect_apfs_is_hidden_without_the_exact_target_and_feature() {
	let args = ["recover", "--help"].into_iter().map(OsString::from);
	let Ok(Command::Help(help)) = parse(args) else {
		panic!("recover help must parse");
	};
	assert!(!help.contains("inspect-apfs"));
	let args = [
		"recover",
		"inspect-apfs",
		".exacopy-00000000-0000-7000-8000-000000000001",
	]
	.into_iter()
	.map(OsString::from);
	assert!(parse(args).is_err());
}

#[cfg(not(all(
	target_os = "windows",
	feature = "experimental-windows-bootstrap-inspect"
)))]
#[test]
fn inspect_windows_bootstrap_is_hidden_without_the_exact_target_and_feature() {
	let args = ["recover", "--help"].into_iter().map(OsString::from);
	let Ok(Command::Help(help)) = parse(args) else {
		panic!("recover help must parse");
	};
	assert!(!help.contains("inspect-windows-bootstrap"));
	let args = ["recover", "inspect-windows-bootstrap", "--help"]
		.into_iter()
		.map(OsString::from);
	assert!(parse(args).is_err());
}
