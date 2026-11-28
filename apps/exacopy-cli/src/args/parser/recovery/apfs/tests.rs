use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;

use super::*;

const JOB: &str = ".exacopy-00000000-0000-7000-8000-00000000000a";

fn arguments() -> Vec<OsString> {
	[
		"recover",
		NAME,
		JOB,
		"--stage-container",
		"/private/tmp/owned/private",
		"--managed-apfs",
		"--owner-profile-id",
		"11111111111111111111111111111111",
		"--owner-key",
		"123456789a123456789a123456789a123456789a123456789a123456789a1234",
		"--destination-root-id",
		"11111111111171118111111111111111",
		"--format",
		"json",
	]
	.into_iter()
	.map(OsString::from)
	.collect()
}

#[test]
fn inspect_apfs_requires_independent_exact_selectors_and_keeps_raw_container_bytes() {
	let mut args = arguments();
	let raw = OsString::from_vec(b"/private/tmp/owned/private-\xff".to_vec());
	args[4] = raw.clone();
	let Ok(Command::InspectApfs(command)) = crate::args::parse(args.into_iter()) else {
		panic!("explicit managed APFS inspection must parse");
	};
	assert_eq!(command.stage_container.as_os_str(), raw.as_os_str());
	assert_eq!(command.job.to_string(), JOB);
	assert_eq!(command.owner_profile.as_bytes(), &[0x11; 16]);
	assert_eq!(command.owner_key[0], 0x12);

	for (index, replacement) in [
		(2, ".exacopy-00000000-0000-7000-8000-00000000000A"),
		(2, ".exacopy-00000000-0000-4000-8000-00000000000a"),
		(2, "./.exacopy-00000000-0000-7000-8000-00000000000a"),
		(4, "relative"),
		(7, "00000000000000000000000000000000"),
		(9, "malformed"),
		(11, "00000000000000000000000000000000"),
	] {
		let mut candidate = arguments();
		candidate[index] = replacement.into();
		assert!(
			crate::args::parse(candidate.into_iter()).is_err(),
			"{index}"
		);
	}
	for index in [3, 5, 6, 8, 10] {
		let mut candidate = arguments();
		let count = if index == 5 { 1 } else { 2 };
		candidate.drain(index..index + count);
		assert!(
			crate::args::parse(candidate.into_iter()).is_err(),
			"{index}"
		);
	}
}
