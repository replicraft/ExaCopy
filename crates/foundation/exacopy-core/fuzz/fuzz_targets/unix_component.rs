//! Checks raw Unix filename acceptance and round-trip preservation.
#![no_main]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use libfuzzer_sys::fuzz_target;

use exacopy_core::UnixComponent;

const BASELINE_NAME_LIMIT: usize = 255;
const NUL: u8 = 0;

fn accepts_raw_name(input: &[u8]) -> bool {
	if input.len() > BASELINE_NAME_LIMIT || input.contains(&NUL) {
		return false;
	}
	let mut parts = Path::new(OsStr::from_bytes(input)).components();
	// Compare bytes because the standard path iterator can normalize separators and dots.
	matches!(parts.next(), Some(Component::Normal(name)) if name.as_bytes() == input)
		&& parts.next().is_none()
}

fuzz_target!(|input: &[u8]| {
	let actual = UnixComponent::new(input);
	assert_eq!(actual.is_ok(), accepts_raw_name(input));
	if let Ok(component) = actual {
		assert_eq!(component.as_bytes(), input);
	}
});
