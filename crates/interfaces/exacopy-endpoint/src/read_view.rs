/// A held, read-only view of a live logical byte stream with a captured extent.
///
/// Implementations bind every read and recheck to the same admitted object.
/// A successful recheck describes a live observation within the adapter's
/// change-detection limits. Ordinary reads may update access times.
pub trait ReadView {
	/// The adapter's error when a read or observation cannot complete.
	type Error;

	/// Returns the logical byte length captured at admission.
	fn length(&self) -> u64;

	/// Confirms the captured observation, including EOF at the recorded length.
	///
	/// # Errors
	/// Returns an error when identity, required observations, or EOF cannot be confirmed.
	fn recheck_observation(&self) -> Result<(), Self::Error>;

	/// Fills `buffer` synchronously from `offset` within the captured extent.
	///
	/// Reads are positioned and leave any underlying cursor unchanged.
	///
	/// # Errors
	/// Returns an error for an out-of-bounds or incomplete read. The buffer may
	/// contain partial data after a failure.
	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error>;
}
