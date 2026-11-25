// Keep the optional hax release library linked into the extraction build only.
#[cfg(feature = "proof-extraction")]
use hax_lib as _;

/// Returns the exclusive end of a nonempty range fully contained in the file.
///
/// A zero-byte file admits no write range. Offsets and lengths are logical byte counts.
///
/// ```
/// use exacopy_model::checked_range_end;
///
/// assert_eq!(checked_range_end(8, 5, 3), Some(8));
/// assert_eq!(checked_range_end(8, 5, 4), None);
/// ```
#[must_use]
pub fn checked_range_end(file_len: u64, start: u64, len: u64) -> Option<u64> {
	if len == 0 {
		return None;
	}
	let end = start.checked_add(len)?;
	if end > file_len {
		return None;
	}
	Some(end)
}
