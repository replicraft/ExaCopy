//! Boundary cases for validated Unix component bytes.

use exacopy_core::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};

#[test]
fn components_preserve_raw_bytes_and_redact_debug_output() {
	let raw = b"file\\name-\xff";
	let component = UnixComponent::new(raw).unwrap();
	assert_eq!(component.as_bytes(), raw);
	assert_eq!(format!("{component:?}"), "UnixComponent(<redacted>)");
	assert!(UnixComponent::new(&[b'x'; MAX_UNIX_COMPONENT_BYTES]).is_ok());
}

#[test]
fn components_reject_traversal_and_path_like_inputs() {
	let too_long = [b'x'; MAX_UNIX_COMPONENT_BYTES + 1];
	let invalid = [
		(&b""[..], NameError::Empty),
		(&too_long[..], NameError::TooLong),
		(&b"."[..], NameError::Reserved),
		(&b".."[..], NameError::Reserved),
		(&b"/absolute"[..], NameError::Separator),
		(&b"nested/name"[..], NameError::Separator),
		(&b"truncated\0name"[..], NameError::Nul),
	];
	for (bytes, expected) in invalid {
		let error = UnixComponent::new(bytes).unwrap_err();
		assert_eq!(error, expected);
		assert!(!error.to_string().is_empty());
	}
}
