use super::{
	FrontdoorError, MAX_AUTHORITY_BYTES, MAX_REMOTE_PATH_BYTES, RemoteOperand, RemotePath,
};

#[test]
fn byte_parser_keeps_remote_names_and_roots() {
	let relative =
		RemoteOperand::parse_bytes(br"Reader@Archive.EXAMPLE.:C:\CON:stream./a\leaf").unwrap();
	assert!(matches!(
		relative.path(),
		RemotePath::AccountRelative(br"C:\CON:stream./a\leaf")
	));

	let absolute_text = "reader@[2001:db8::1]:/dir/e\u{301}-𐐀:@file";
	let absolute = RemoteOperand::parse_bytes(absolute_text.as_bytes()).unwrap();
	assert!(matches!(
		absolute.path(),
		RemotePath::Absolute(b"/dir/e\xcc\x81-\xf0\x90\x90\x80:@file")
	));

	let raw = RemoteOperand::parse_bytes(b"reader@archive.example:dir/\xff").unwrap();
	assert!(matches!(
		raw.path(),
		RemotePath::AccountRelative(b"dir/\xff")
	));
}

#[test]
fn byte_parser_checks_operand_before_remote_path() {
	let invalid_authorities: [&[u8]; 3] = [
		b"",
		b"reader@2001:db8::1:../file",
		b"reader\xff@archive.example:../file",
	];
	for rejected in invalid_authorities {
		assert!(
			matches!(
				RemoteOperand::parse_bytes(rejected),
				Err(FrontdoorError::Operand)
			),
			"unexpected diagnosis for {rejected:?}"
		);
	}
	assert!(matches!(
		RemoteOperand::parse_bytes(b"reader@archive.example:../file"),
		Err(FrontdoorError::RemotePath)
	));
}

#[test]
fn byte_parser_distinguishes_operand_length_from_path_length() {
	let mut input = b"reader@archive.example:".to_vec();
	input.extend_from_slice(&b"a/".repeat(MAX_REMOTE_PATH_BYTES / 2 - 1));
	input.extend_from_slice(b"ab");
	assert!(RemoteOperand::parse_bytes(&input).is_ok());

	input.extend_from_slice(b"/a");
	assert!(matches!(
		RemoteOperand::parse_bytes(&input),
		Err(FrontdoorError::RemotePath)
	));
	input.resize(MAX_AUTHORITY_BYTES + MAX_REMOTE_PATH_BYTES + 2, b'a');
	assert!(matches!(
		RemoteOperand::parse_bytes(&input),
		Err(FrontdoorError::Operand)
	));
}
