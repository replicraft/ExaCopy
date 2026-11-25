use core::fmt;

/// The maximum number of bytes in a Unix component accepted by the local baseline.
pub const MAX_UNIX_COMPONENT_BYTES: usize = 255;

/// A single lossless, relative Unix filename component.
///
/// Filesystem-specific name equivalence and exclusive creation remain adapter responsibilities.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct UnixComponent<'a>(&'a [u8]);

impl<'a> UnixComponent<'a> {
	/// Validates a component without copying, decoding, or normalizing its bytes.
	///
	/// # Errors
	/// Returns [`NameError`] for an empty, oversized, special, or path-like name.
	pub fn new(bytes: &'a [u8]) -> Result<Self, NameError> {
		if bytes.is_empty() {
			return Err(NameError::Empty);
		}
		if bytes.len() > MAX_UNIX_COMPONENT_BYTES {
			return Err(NameError::TooLong);
		}
		if matches!(bytes, b"." | b"..") {
			return Err(NameError::Reserved);
		}
		if bytes.contains(&b'/') {
			return Err(NameError::Separator);
		}
		if bytes.contains(&0) {
			return Err(NameError::Nul);
		}
		Ok(Self(bytes))
	}

	/// Returns the original bytes for a descriptor-relative filesystem operation.
	#[must_use]
	pub const fn as_bytes(self) -> &'a [u8] {
		self.0
	}
}

impl fmt::Debug for UnixComponent<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("UnixComponent(<redacted>)")
	}
}

/// A filename outside the Unix component contract.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NameError {
	/// The component is empty.
	Empty,
	/// The component exceeds the baseline byte limit.
	TooLong,
	/// The component is `.` or `..`.
	Reserved,
	/// The component contains a Unix path separator.
	Separator,
	/// The component contains an embedded NUL.
	Nul,
}

impl fmt::Display for NameError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Empty => formatter.write_str("filename component is empty"),
			Self::TooLong => write!(
				formatter,
				"filename component exceeds {MAX_UNIX_COMPONENT_BYTES} bytes"
			),
			Self::Reserved => {
				formatter.write_str("filename component refers to the current or parent directory")
			}
			Self::Separator => formatter.write_str("filename component contains a path separator"),
			Self::Nul => formatter.write_str("filename component contains an embedded NUL"),
		}
	}
}

impl core::error::Error for NameError {}
