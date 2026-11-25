use core::fmt;

/// The standard unkeyed BLAKE3-256 digest of a complete observed byte stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentDigest(pub(super) blake3::Hash);

impl ContentDigest {
	/// Returns the 32 bytes of the digest in standard BLAKE3 output order.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		self.0.as_bytes()
	}
}

impl fmt::Display for ContentDigest {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(&self.0, formatter)
	}
}
