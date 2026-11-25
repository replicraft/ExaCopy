use exacopy_endpoint::UnixComponent;
use tokio::time::Instant;

use super::{
	Extent, FileObservation, OPERATION_TIMEOUT, ReadOnlySftp, ReadRange, Session, Source,
	encode_path,
};
use crate::error::Error;

/// A file's live metadata and the exact interval consumed through one completed window.
///
/// The caller owns the bytes and any digest computed from them. The observation
/// covers only this window and carries no reusable remote identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowObservation {
	offset: u64,
	length: u64,
	file: FileObservation,
}

impl WindowObservation {
	/// Returns the starting byte offset in the file.
	#[must_use]
	pub const fn offset(&self) -> u64 {
		self.offset
	}

	/// Returns the number of bytes delivered in this window.
	#[must_use]
	pub const fn length(&self) -> u64 {
		self.length
	}

	/// Returns the matching live SFTP v3 file observations around the window.
	#[must_use]
	pub const fn file(&self) -> FileObservation {
		self.file
	}
}

/// A held, read-only SFTP file that can serve several bounded positioned windows.
///
/// All windows use the same open handle. Unconfirmed operations and unfinished
/// drops fence the connection. Observations reflect live server metadata at
/// SFTP v3 resolution.
pub struct RemotePositionedRead<'a> {
	parent: &'a mut Option<Session>,
	session: Option<Session>,
	source: Source,
}

/// A bounded positioned interval on a held SFTP source.
///
/// Reads are provisional until [finish](Self::finish) succeeds. The window
/// deadline includes caller processing between reads.
pub struct RemoteReadWindow<'a> {
	parent: &'a mut Option<Session>,
	session: Option<Session>,
	source: &'a Source,
	range: ReadRange,
	deadline: Instant,
}

impl ReadOnlySftp {
	/// Opens one read-only handle for bounded positioned reads.
	///
	/// The handle may remain open across windows while the connection stays
	/// live. Opening compares the named and held observations and has its own
	/// 20-second deadline.
	///
	/// # Errors
	/// Refuses invalid paths, unsupported sources, changed observations and
	/// session failures. Failure after path admission fences the session.
	pub async fn open_positioned(
		&mut self,
		path: &[UnixComponent<'_>],
	) -> Result<RemotePositionedRead<'_>, Error> {
		let path = encode_path(path)?;
		let deadline = Instant::now() + OPERATION_TIMEOUT;
		let (session, source) = self.open_source(path, Extent::Positioned, deadline).await?;
		Ok(RemotePositionedRead {
			parent: &mut self.session,
			session: Some(session),
			source,
		})
	}
}

impl RemotePositionedRead<'_> {
	/// Returns the server-reported file metadata captured when the handle opened.
	#[must_use]
	pub const fn observation(&self) -> FileObservation {
		self.source.before
	}

	/// Starts a positive interval within the observed file extent.
	///
	/// The window admits up to 128 MiB and 4,096 data requests. Its single
	/// 20-second deadline covers the held and named checks, data reads, and
	/// window completion. Each new window has a separate budget.
	///
	/// # Errors
	/// Refuses invalid or oversized intervals, changed observations and
	/// session failures. A failed or cancelled admission fences the session.
	pub async fn begin_window(
		&mut self,
		offset: u64,
		length: u64,
	) -> Result<RemoteReadWindow<'_>, Error> {
		let mut session = self.session.take().ok_or(Error::Closed)?;
		let deadline = Instant::now() + OPERATION_TIMEOUT;
		if length == 0 {
			return Err(Error::Limit);
		}
		let range = ReadRange::new(offset, length, self.source.before.length)?;
		session
			.run(deadline, async |wire| self.source.recheck(wire).await)
			.await?;
		Ok(RemoteReadWindow {
			parent: &mut self.session,
			session: Some(session),
			source: &self.source,
			range,
			deadline,
		})
	}

	/// Confirms EOF at the observed file length, closes the handle and restores the session.
	///
	/// This has a separate 20-second deadline. The resulting metadata and EOF
	/// observation carries no evidence about the file contents. Completed
	/// windows describe only the intervals they cover.
	///
	/// # Errors
	/// Refuses missing EOF, changed observations and session failures. A
	/// failed or cancelled finish fences the session.
	pub async fn finish(self) -> Result<FileObservation, Error> {
		let mut session = self.session.ok_or(Error::Closed)?;
		let observation = session
			.run(Instant::now() + OPERATION_TIMEOUT, async move |wire| {
				self.source.finish(wire).await
			})
			.await?;
		*self.parent = Some(session);
		Ok(observation)
	}
}

impl RemoteReadWindow<'_> {
	/// Fills up to the supplied buffer's length from the current window offset.
	///
	/// A positive short read advances by the returned count. Zero signals
	/// consumption of the admitted interval. Call [finish](Self::finish) to
	/// recheck the file and release the window.
	///
	/// # Errors
	/// Buffer lengths outside 1–32 KiB, early EOF, request exhaustion and
	/// transport failures fence the session. Discard bytes from a failed call.
	pub async fn read_next(&mut self, output: &mut [u8]) -> Result<usize, Error> {
		let mut session = self.session.take().ok_or(Error::Closed)?;
		let count = session
			.run(self.deadline, async |wire| {
				self.range.read_into(wire, &self.source.file, output).await
			})
			.await?;
		self.session = Some(session);
		Ok(count)
	}

	/// Confirms exact window consumption and rechecks held and named metadata.
	///
	/// The result covers the admitted interval. The handle remains open for
	/// further windows or for the separate file EOF and close checks.
	///
	/// # Errors
	/// Incomplete consumption, changed observations and session failures
	/// fence the connection.
	pub async fn finish(self) -> Result<WindowObservation, Error> {
		let mut session = self.session.ok_or(Error::Closed)?;
		session
			.run(self.deadline, async |wire| {
				self.range.require_complete()?;
				self.source.recheck(wire).await
			})
			.await?;
		*self.parent = Some(session);
		Ok(WindowObservation {
			offset: self.range.start(),
			length: self.range.length(),
			file: self.source.before,
		})
	}
}
