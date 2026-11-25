use super::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent, WindowsNameError};

fn assert_refused(name: &str, expected: WindowsNameError) {
	let units: Vec<u16> = name.encode_utf16().collect();
	assert_eq!(WindowsComponent::new(&units), Err(expected), "{name:?}");
}

#[test]
fn admits_original_code_units_including_unpaired_surrogates() {
	let raw = [0xD800, 0x0301, 0xD83D, 0xDE00, 0xDC00, 0xFFFF];
	let admitted = WindowsComponent::new(&raw).expect("native UTF-16 units are not decoded");
	assert_eq!(admitted.as_units(), &raw);
	assert!(core::ptr::eq(admitted.as_units(), raw.as_slice()));

	let decomposed = [u16::from(b'e'), 0x0301];
	let composed = [0x00E9];
	assert_ne!(
		WindowsComponent::new(&decomposed).expect("decomposed spelling"),
		WindowsComponent::new(&composed).expect("composed spelling"),
	);
}

#[test]
fn length_limit_counts_code_units_instead_of_decoded_characters() {
	let mut name = Vec::new();
	for _ in 0..127 {
		name.extend([0xD83D, 0xDE00]);
	}
	name.push(u16::from(b'x'));
	assert_eq!(name.len(), MAX_WINDOWS_COMPONENT_UNITS);
	let admitted = WindowsComponent::new(&name).expect("maximum length");
	assert_eq!(admitted.as_units().len(), MAX_WINDOWS_COMPONENT_UNITS);

	name.push(0xD800);
	assert_eq!(WindowsComponent::new(&name), Err(WindowsNameError::TooLong));
	assert_eq!(WindowsComponent::new(&[]), Err(WindowsNameError::Empty));
}

#[test]
fn refuses_path_and_stream_syntax() {
	use WindowsNameError::{Colon, DotComponent, Separator};

	for name in [".", ".."] {
		assert_refused(name, DotComponent);
	}
	for name in [
		"dir/sub",
		"dir\\sub",
		"/file",
		"\\file",
		"..\\file",
		"\\\\server\\share",
		"\\\\?\\Volume",
		"\\\\.\\PhysicalDrive0",
		"file/",
		"file\\",
	] {
		assert_refused(name, Separator);
	}
	for name in ["C:", "D:relative", "file:stream", "file::$DATA", ":stream"] {
		assert_refused(name, Colon);
	}
}

#[test]
fn refuses_spellings_subject_to_edge_rewriting() {
	for name in [
		" file",
		" file.txt",
		"file ",
		"file.",
		"file..",
		"...",
		"  ",
	] {
		assert_refused(name, WindowsNameError::AmbiguousEdge);
	}

	for name in [
		".temp",
		"..hidden",
		"two words",
		"a.b.c",
		"x\u{00A0}",
		"\u{00A0}x",
	] {
		let raw: Vec<_> = name.encode_utf16().collect();
		assert_eq!(WindowsComponent::new(&raw).expect(name).as_units(), raw);
	}
}

#[test]
fn interior_code_unit_admission_matches_the_literal_filename_alphabet() {
	let forbidden = [
		'\0', '\u{0001}', '\u{0002}', '\u{0003}', '\u{0004}', '\u{0005}', '\u{0006}', '\u{0007}',
		'\u{0008}', '\t', '\n', '\u{000B}', '\u{000C}', '\r', '\u{000E}', '\u{000F}', '\u{0010}',
		'\u{0011}', '\u{0012}', '\u{0013}', '\u{0014}', '\u{0015}', '\u{0016}', '\u{0017}',
		'\u{0018}', '\u{0019}', '\u{001A}', '\u{001B}', '\u{001C}', '\u{001D}', '\u{001E}',
		'\u{001F}', '<', '>', ':', '"', '/', '\\', '|', '?', '*',
	];
	let mut raw = [u16::from(b'x'), 0, u16::from(b'x')];
	for unit in 0..=u16::MAX {
		raw[1] = unit;
		let valid = char::from_u32(u32::from(unit)).is_none_or(|ch| !forbidden.contains(&ch));
		match WindowsComponent::new(&raw) {
			Ok(name) => {
				assert!(valid, "accepted forbidden code unit {unit:#06x}");
				assert_eq!(name.as_units(), &raw);
			}
			Err(error) => assert!(!valid, "refused code unit {unit:#06x}: {error}"),
		}
	}
}

#[test]
fn returns_typed_character_errors() {
	assert_refused("name\0suffix", WindowsNameError::Nul);
	for name in [
		"a<b",
		"a>b",
		"a\"b",
		"a|b",
		"a?b",
		"a*b",
		"a\nb",
		"a\u{001F}b",
	] {
		assert_refused(name, WindowsNameError::InvalidCharacter);
	}
}

#[test]
fn refuses_device_aliases_with_case_variants_spaces_and_extensions() {
	let devices = [
		"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5",
		"COM6", "COM7", "COM8", "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4",
		"LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
	];
	for device in devices {
		for case_bits in 0..(1 << device.len()) {
			let spelling: String = device
				.chars()
				.enumerate()
				.map(|(index, ch)| {
					if case_bits & (1 << index) == 0 {
						ch
					} else {
						ch.to_ascii_lowercase()
					}
				})
				.collect();
			for suffix in ["", ".txt", ".tar.gz", " .tmp"] {
				assert_refused(
					&format!("{spelling}{suffix}"),
					WindowsNameError::ReservedDevice,
				);
			}
		}
	}
}

#[test]
fn device_prefixes_and_similar_characters_do_not_change_a_filename() {
	for name in [
		"connect",
		"auxiliary.txt",
		"prn-old",
		"nul$",
		"com10.txt",
		"lpt12.txt",
		"lpt⁴.txt",
		"com１.txt",
		"ＣＯＮ.txt",
		"conin",
		"conout$-old",
		".nul.txt",
	] {
		let raw: Vec<_> = name.encode_utf16().collect();
		assert_eq!(WindowsComponent::new(&raw).expect(name).as_units(), raw);
	}
}

#[test]
fn debug_redacts_original_units() {
	let units: Vec<_> = "private-source-name".encode_utf16().collect();
	let name = WindowsComponent::new(&units).expect("ordinary name");
	assert_eq!(format!("{name:?}"), "WindowsComponent(<redacted>)");
}

#[test]
fn refusal_messages_identify_the_reason_without_echoing_the_name() {
	use WindowsNameError::{
		AmbiguousEdge, Colon, DotComponent, Empty, InvalidCharacter, Nul, ReservedDevice,
		Separator, TooLong,
	};

	let private = "private-source-name";
	let names = [
		(String::new(), Empty, "empty"),
		(
			private.repeat(MAX_WINDOWS_COMPONENT_UNITS),
			TooLong,
			"UTF-16 code units",
		),
		("..".to_owned(), DotComponent, "current or parent directory"),
		(format!("{private}."), AmbiguousEdge, "ambiguous"),
		(format!("{private}\0"), Nul, "embedded NUL"),
		(format!("{private}\\data"), Separator, "path separator"),
		(format!("{private}:data"), Colon, "colon"),
		(
			format!("{private}?"),
			InvalidCharacter,
			"reserved character",
		),
		(format!("NUL.{private}"), ReservedDevice, "device name"),
	];

	for (name, expected, explanation) in names {
		let units: Vec<_> = name.encode_utf16().collect();
		let error = WindowsComponent::new(&units).expect_err("a known refusal");
		assert_eq!(error, expected);
		let diagnostic = error.to_string();
		assert!(diagnostic.contains(explanation), "{diagnostic:?}");
		assert!(!diagnostic.contains(private), "{diagnostic:?}");
	}
}
