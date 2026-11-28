use std::ffi::OsString;
use std::fmt::Write as _;
use std::os::windows::ffi::OsStringExt as _;

use super::*;

fn arguments() -> Vec<OsString> {
	[
		"recover",
		NAME,
		"--root",
		r"D:\managed\private",
		"--volume-guid",
		"01234567-89ab-cdef-0123-456789abcdef",
		"--volume-serial",
		"18446744073709551615",
		"--root-file-id",
		"0123456789abcdef1032547698badcfe",
		"--owner-profile-id",
		"41414141414141414141414141414141",
		"--owner-key",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"--job-id",
		"018d45be-0000-7000-8000-000000000001",
		"--managed-ntfs",
	]
	.into_iter()
	.map(OsString::from)
	.collect()
}

#[test]
fn windows_bootstrap_parser_requires_exact_independent_selection() {
	let mut args = arguments();
	let mut root: Vec<u16> = r"D:\managed\private-".encode_utf16().collect();
	root.push(0xd800);
	let raw = OsString::from_wide(&root);
	args[3] = raw.clone();
	args.extend([OsString::from("--format"), OsString::from("json")]);
	let Ok(Command::InspectWindowsBootstrap(command)) = crate::args::parse(args.into_iter()) else {
		panic!("independently selected bootstrap should parse");
	};
	assert_eq!(command.root.as_os_str(), raw.as_os_str());
	assert_eq!(
		command.root_identity.volume_guid(),
		b"01234567-89ab-cdef-0123-456789abcdef"
	);
	assert_eq!(command.root_identity.volume_serial(), u64::MAX);
	assert_eq!(
		command.root_identity.file_id(),
		&[
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
			0xdc, 0xfe,
		]
	);
	assert_eq!(command.profile.as_bytes(), &[0x41; 16]);
	assert_eq!(command.owner_key[0], 0xd7);
	assert_eq!(
		command.job.as_bytes(),
		&[
			0x01, 0x8d, 0x45, 0xbe, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1
		]
	);
	assert!(crate::args::parse(arguments().into_iter()).is_ok());

	for (index, value) in [
		(3, r"\\server\share\private"),
		(3, r"\\?\D:\private"),
		(3, r"D:private"),
		(3, "D:/private"),
		(3, r"D:\"),
		(5, "01234567-89AB-cdef-0123-456789abcdef"),
		(7, "18446744073709551616"),
		(7, "+1"),
		(7, "01"),
		(9, "00000000000000000000000000000000"),
		(9, "0123456789abcdef1032547698badcf"),
		(11, "00000000000000000000000000000000"),
		(13, "malformed"),
		(15, "018d45be-0000-7000-8000-00000000000A"),
		(15, "018d45be-0000-4000-8000-000000000001"),
		(15, "018d45be000070008000000000000001"),
	] {
		let mut candidate = arguments();
		candidate[index] = value.into();
		assert!(
			crate::args::parse(candidate.into_iter()).is_err(),
			"{index}"
		);
	}
	for index in [2, 4, 6, 8, 10, 12, 14, 16] {
		let mut candidate = arguments();
		let count = if index == 16 { 1 } else { 2 };
		candidate.drain(index..index + count);
		assert!(
			crate::args::parse(candidate.into_iter()).is_err(),
			"{index}"
		);
	}
	// Public key from RFC 8032 section 7.1, test 2.
	let foreign_key = [
		0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
		0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
		0x66, 0x0c,
	];
	assert_ne!(command.owner_key, foreign_key);
	let mut alternate_key = String::with_capacity(foreign_key.len() * 2);
	for byte in foreign_key {
		write!(alternate_key, "{byte:02x}").unwrap();
	}

	// Each alternate can stand alone. A duplicate cannot override or coexist
	// with either independently selected identity.
	for (value_index, alternate) in [
		(3, r"E:\another\private"),
		(5, "fedcba98-7654-3210-fedc-ba9876543210"),
		(7, "1"),
		(9, "fedcba9876543210fedcba9876543210"),
		(11, "42424242424242424242424242424242"),
		(13, alternate_key.as_str()),
		(15, "018d45be-0000-7000-8000-000000000002"),
	] {
		let mut alternate_only = arguments();
		alternate_only[value_index] = alternate.into();
		let Ok(Command::InspectWindowsBootstrap(alternate_only)) =
			crate::args::parse(alternate_only.into_iter())
		else {
			panic!("alternate selector at {value_index} must be valid on its own");
		};
		if value_index == 13 {
			assert_eq!(alternate_only.owner_key, foreign_key);
		}
		let mut duplicate = arguments();
		duplicate.extend([duplicate[value_index - 1].clone(), alternate.into()]);
		assert!(
			crate::args::parse(duplicate.into_iter()).is_err(),
			"duplicate selector at {value_index}"
		);
	}
	for extra in [["--format", "human"], ["--private-key", "file"]] {
		let mut candidate = arguments();
		candidate.extend(extra.map(OsString::from));
		assert!(crate::args::parse(candidate.into_iter()).is_err());
	}
}
