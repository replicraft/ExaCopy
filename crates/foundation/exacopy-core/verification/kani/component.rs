//! Symbolic checks for the Unix component validator in P-013.

use crate::{NameError, UnixComponent};

const SPEC_LIMIT: usize = 255;
const SCAN_WIDTH: usize = 16;
const STORAGE_BYTES: usize = SPEC_LIMIT + 1;

#[kani::proof]
#[kani::unwind(20)]
fn checked_unix_component_matches_byte_specification() {
	let storage = kani::any::<[u8; STORAGE_BYTES]>();
	let len = usize::from(kani::any::<u8>());
	let raw = &storage[..len];

	// Each loop has at most sixteen iterations, including across longer names.
	let mut has_slash = false;
	let mut has_nul = false;
	for block in 0..STORAGE_BYTES / SCAN_WIDTH {
		for offset in 0..SCAN_WIDTH {
			let index = block * SCAN_WIDTH + offset;
			let byte = storage[index];
			has_slash |= (index < len) & (byte == b'/');
			has_nul |= (index < len) & (byte == 0);
		}
	}
	let reserved =
		(len == 1 && storage[0] == b'.') || (len == 2 && storage[0] == b'.' && storage[1] == b'.');
	let expected = if len == 0 {
		Some(NameError::Empty)
	} else if reserved {
		Some(NameError::Reserved)
	} else if has_slash {
		Some(NameError::Separator)
	} else if has_nul {
		Some(NameError::Nul)
	} else {
		None
	};

	let actual = UnixComponent::new(raw);
	kani::assert(
		actual.err() == expected,
		"validation matches the Unix byte specification",
	);
	if let Ok(component) = actual {
		kani::assert(
			core::ptr::eq(component.as_bytes(), raw),
			"accepted name borrows its original bytes",
		);
	}
	kani::cover!(
		actual.is_ok() && len == SPEC_LIMIT,
		"valid maximum-length name"
	);
	kani::cover!(
		actual.is_ok() && len == 1 && storage[0] == u8::MAX,
		"valid non-UTF-8 name"
	);
	kani::cover!(
		matches!(actual, Err(NameError::Empty)),
		"empty name rejected"
	);
	kani::cover!(
		matches!(actual, Err(NameError::Reserved)) && len == 1,
		"current directory rejected"
	);
	kani::cover!(
		matches!(actual, Err(NameError::Reserved)) && len == 2,
		"parent directory rejected"
	);
	kani::cover!(
		matches!(actual, Err(NameError::Separator)) && has_nul,
		"slash takes precedence over NUL"
	);
	kani::cover!(
		matches!(actual, Err(NameError::Nul)),
		"NUL without slash rejected"
	);
}

#[kani::proof]
#[kani::unwind(1)]
fn oversized_unix_component_at_first_invalid_length() {
	let storage = kani::any::<[u8; STORAGE_BYTES]>();
	let actual = UnixComponent::new(&storage);
	kani::assert(
		actual.err() == Some(NameError::TooLong),
		"every 256-byte name is oversized",
	);
	kani::cover!(
		matches!(actual, Err(NameError::TooLong)) && storage[0] == 0 && storage[1] == b'/',
		"oversize takes precedence over slash and NUL"
	);
}
