use super::*;

#[test]
fn text_password_requires_exact_unicode_without_normalization() {
	let original = "example-é-e\u{301}-𐐀";
	assert_eq!(
		password_text(OsString::from(original)).as_deref(),
		Some(original)
	);
}

#[cfg(unix)]
#[test]
fn unix_remote_and_local_paths_retain_raw_bytes() {
	use std::os::unix::ffi::OsStringExt as _;

	let raw = b"reader@archive.example:dir/\xff";
	assert_eq!(remote_bytes(OsStr::from_bytes(raw)).unwrap(), raw);
	let configured = PathBuf::from(OsStr::from_bytes(b"/private/\xff.json"));
	assert_eq!(protected_path(configured.clone()).unwrap(), configured);
	assert!(destination_path(Path::new(OsStr::from_bytes(b"./out/\xff"))).is_ok());
	assert!(password_text(OsString::from_vec(vec![0xff])).is_none());
	assert!(protected_path("/private/../other.json".into()).is_err());
}

#[cfg(windows)]
#[test]
fn windows_remote_operands_and_passwords_refuse_unpaired_surrogates() {
	use std::os::windows::ffi::OsStringExt as _;

	let text = "reader@archive.example:dir/e\u{301}-𐐀";
	assert_eq!(remote_bytes(OsStr::new(text)).unwrap(), text.as_bytes());
	let mut units: Vec<u16> = text.encode_utf16().collect();
	units.push(0xd800);
	let malformed = OsString::from_wide(&units);
	assert!(matches!(
		remote_bytes(&malformed),
		Err(FrontdoorError::Operand)
	));
	assert!(password_text(malformed).is_none());
}

#[cfg(windows)]
#[test]
fn windows_local_paths_use_native_absolute_and_component_rules() {
	for selected in [
		r"C:\protected\profile.json",
		"D:/private/profile.json",
		r"\\server\share\protected\profile.json",
	] {
		let path = PathBuf::from(selected);
		assert_eq!(protected_path(path.clone()).unwrap(), path);
		assert!(destination_path(&path).is_ok());
	}
	assert!(destination_path(Path::new(r".\destination\file")).is_ok());
	assert!(protected_path(r".\destination\file".into()).is_err());

	for refused in [
		r"C:relative\profile.json",
		r"\current-drive\profile.json",
		r"C:\",
		r"\\server\share",
		r"\\?\C:\protected\profile.json",
		r"\\.\C:\protected\profile.json",
		r"C:\private\..\profile.json",
		r"C:\private\.\profile.json",
		r"C:\private\profile.json\",
		r"C:\private\profile.json:data",
		r"C:\private\CON.txt",
		r"C:\private\profile.json.",
	] {
		assert!(protected_path(refused.into()).is_err(), "{refused}");
		assert!(destination_path(Path::new(refused)).is_err(), "{refused}");
	}
}

#[cfg(windows)]
#[test]
fn windows_local_path_does_not_convert_native_units_to_remote_text() {
	use std::os::windows::ffi::OsStringExt as _;

	let mut units: Vec<u16> = r"C:\private\".encode_utf16().collect();
	units.push(0xd800);
	let path = PathBuf::from(OsString::from_wide(&units));
	let lexical = protected_path(path).unwrap();
	assert_eq!(lexical.as_os_str().encode_wide().collect::<Vec<_>>(), units);
}

#[test]
fn key_passphrase_rejects_empty_nul_and_over_limit_values() {
	assert!(key_passphrase(OsString::new(), 3).is_none());
	assert!(key_passphrase(OsString::from("a\0b"), 3).is_none());
	assert!(key_passphrase(OsString::from("four"), 3).is_none());
	assert_eq!(&*key_passphrase(OsString::from("yes"), 3).unwrap(), b"yes");
}

#[cfg(unix)]
#[test]
fn unix_key_passphrase_retains_non_unicode_bytes() {
	use std::os::unix::ffi::OsStringExt as _;

	assert_eq!(
		&*key_passphrase(OsString::from_vec(vec![0xff]), 1).unwrap(),
		&[0xff]
	);
}

#[cfg(windows)]
#[test]
fn windows_key_passphrase_uses_exact_utf8_and_refuses_unpaired_surrogates() {
	use std::os::windows::ffi::OsStringExt as _;

	let text = "e\u{301}-𐐀";
	let mut malformed: Vec<u16> = text.encode_utf16().collect();
	malformed.push(0xdc00);
	assert!(key_passphrase(OsString::from_wide(&malformed), 128).is_none());
	assert_eq!(
		&*key_passphrase(OsString::from(text), text.len()).unwrap(),
		text.as_bytes()
	);
}
