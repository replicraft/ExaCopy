use std::io::{self, Read, Seek, Write};

/// The full file barrier performed by an admitted journal segment adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JournalFileBarrier {
	/// Synchronizes file content and metadata with the platform's full file barrier.
	SyncAll,
	/// Requests Darwin `F_FULLFSYNC`.
	DarwinFullFsync,
}

/// Exclusive I/O to one already admitted journal segment.
///
/// The adapter supplies one held object with exclusive mutation access and one cursor shared by
/// reads, writes and seeks. Its acquisition establishes the required namespace ownership and
/// retains any required lease while the writer can use this capability.
pub trait JournalSegment: Read + Write + Seek {
	/// The file barrier used by every call to [`Self::sync`].
	const BARRIER: JournalFileBarrier;

	/// Returns the freshly observed length, or `None` if the held object is nonregular.
	///
	/// # Errors
	/// Reports a failed observation of the held object.
	fn regular_length(&self) -> io::Result<Option<u64>>;

	/// Performs the declared full barrier on the held object.
	///
	/// Success reports the file barrier only. Directory persistence and physical power-loss
	/// qualification require independent evidence.
	///
	/// # Errors
	/// Reports any failed or uncertain barrier. The caller must reconcile before writing again.
	fn sync(&self) -> io::Result<()>;
}
