pub(crate) const MAX_BASENAME_BYTES: usize = 255;
pub(crate) const MAX_LOGICAL_LENGTH: u64 = i64::MAX as u64;
pub(crate) const BLAKE3_CODE: u8 = 0;
pub(crate) const REGULAR_CODE: u8 = 0;
pub(crate) const UNIX_BYTES_CODE: u8 = 1;

pub(crate) fn valid_unix_basename(name: &[u8]) -> bool {
	!name.is_empty()
		&& name.len() <= MAX_BASENAME_BYTES
		&& !matches!(name, b"." | b"..")
		&& !name.iter().any(|byte| matches!(byte, b'/' | 0))
}
