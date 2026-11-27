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
	use WindowsNameError::{
		AmbiguousEdge, Colon, DotComponent, InvalidCharacter, Nul, ReservedDevice, Separator,
	};

	let [x, c, o, m, n, space, dot] = [b'x', b'C', b'o', b'M', b'N', b' ', b'.'].map(u16::from);
	let [l, p, t] = [b'L', b'p', b'T'].map(u16::from);
	for unit in 0..=u16::MAX {
		// Surrogates have no scalar value and are valid raw units in every fixture.
		let scalar = char::from_u32(u32::from(unit));
		let forbidden = match scalar {
			Some('\0') => Some(Nul),
			Some('/' | '\\') => Some(Separator),
			Some(':') => Some(Colon),
			Some('\u{0001}'..='\u{001F}') => Some(InvalidCharacter),
			Some('<' | '>' | '"' | '|' | '?' | '*') => Some(InvalidCharacter),
			_ => None,
		};
		let leading = (scalar == Some(' ')).then_some(AmbiguousEdge);
		let trailing = matches!(scalar, Some(' ' | '.')).then_some(AmbiguousEdge);
		let singleton = match scalar {
			Some('.') => Some(DotComponent),
			_ => leading,
		};
		let serial = matches!(scalar, Some('1'..='9' | '¹' | '²' | '³')).then_some(ReservedDevice);
		let con_middle = matches!(scalar, Some('O' | 'o')).then_some(ReservedDevice);

		let cases: [(&[u16], Option<WindowsNameError>); 7] = [
			(&[unit], singleton.or(forbidden)),
			(&[unit, x], leading.or(forbidden)),
			(&[x, unit], trailing.or(forbidden)),
			(&[x, unit, x], forbidden),
			(&[c, o, m, unit, space, dot, x], forbidden.or(serial)),
			(&[l, p, t, unit, space, dot, x], forbidden.or(serial)),
			(&[c, unit, n, space, dot, x], forbidden.or(con_middle)),
		];
		for (raw, expected) in cases {
			match expected {
				Some(error) => assert_eq!(WindowsComponent::new(raw), Err(error), "{raw:04x?}"),
				None => {
					let name = WindowsComponent::new(raw)
						.unwrap_or_else(|error| panic!("refused {raw:04x?}: {error}"));
					assert!(core::ptr::eq(name.as_units(), raw), "{raw:04x?}");
				}
			}
		}
	}
}

#[test]
fn mixed_violations_keep_the_typed_refusal_precedence() {
	use WindowsNameError::{AmbiguousEdge, Colon, InvalidCharacter, Nul, Separator, TooLong};

	for (name, expected) in [
		(" \\file", AmbiguousEdge),
		("file:\0.", AmbiguousEdge),
		("NUL.\0/stream", Nul),
		("NUL./\0stream", Separator),
		("CON.txt:stream?", Colon),
		("CON.txt?:stream", InvalidCharacter),
	] {
		assert_refused(name, expected);
	}

	let mut oversized = [u16::from(b'x'); MAX_WINDOWS_COMPONENT_UNITS + 1];
	oversized[0] = u16::from(b' ');
	oversized[1] = 0;
	assert_eq!(WindowsComponent::new(&oversized), Err(TooLong));
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
