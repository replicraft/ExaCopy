use exacopy_endpoint::UnixComponent;
use russh_sftp::protocol::{
	FileAttributes, Fstat, Open, OpenFlags, Packet, Read, SftpHandle, SftpString, StatusCode,
};
use tokio::time::Instant;

use super::{
	FileObservation, OPERATION_TIMEOUT, ReadOnlySftp, Session, close, encode_path, handle, lstat,
	observation, unexpected,
};
use crate::error::Error;
use crate::wire::Wire;

mod positioned;
mod range;

pub use positioned::{RemotePositionedRead, RemoteReadWindow, WindowObservation};

use range::ReadRange;

/// The largest caller buffer accepted by one streaming read.
pub const MAX_READ_CHUNK_BYTES: usize = 32 * 1024;
/// The largest admitted sequential stream or positioned window.
pub const MAX_STREAM_BYTES: u64 = range::MAX_READ_REQUESTS * MAX_READ_CHUNK_BYTES as u64;
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

/// A sequential reader bound to one open SFTP handle and its SSH session.
///
/// Bytes are provisional until [the final verification](RemoteReadFile::finish)
/// succeeds. Dropping an unfinished reader or cancelling an operation after it
/// starts fences the session. The deadline applies during caller processing.
pub struct RemoteReadFile<'a> {
	parent: &'a mut Option<Session>,
	session: Option<Session>,
	source: Source,
	range: ReadRange,
	deadline: Instant,
}

impl ReadOnlySftp {
	/// Opens a read-only stream after comparing the initial path and handle observations.
	///
	/// This prototype holds one SFTP session exclusively until a successful
	/// finish and allows at most 128 MiB, 4096 data reads and 20 seconds total.
	/// Metadata and EOF are live observations at SFTP v3 resolution.
	///
	/// # Errors
	/// Refuses invalid paths, unsupported sources, changed observations, and
	/// files beyond the request budget. Failure after path admission fences the session.
	pub async fn open_read(
		&mut self,
		path: &[UnixComponent<'_>],
	) -> Result<RemoteReadFile<'_>, Error> {
		let path = encode_path(path)?;
		let deadline = Instant::now() + OPERATION_TIMEOUT;
		let (session, source) = self.open_source(path, Extent::Sequential, deadline).await?;
		let range = ReadRange::new(0, source.before.length, source.before.length)?;
		Ok(RemoteReadFile {
			parent: &mut self.session,
			session: Some(session),
			source,
			range,
			deadline,
		})
	}

	/// Reads a regular file of exactly the buffer's length, with held observations.
	///
	/// This API retains the 4 MiB whole-file limit. Observations reflect live
	/// SFTP v3 metadata. The buffer may contain partial bytes on error.
	///
	/// # Errors
	/// Fails on extent, observation, source kind, read, or close errors.
	pub async fn read_file(
		&mut self,
		path: &[UnixComponent<'_>],
		output: &mut [u8],
	) -> Result<FileObservation, Error> {
		if output.len() > MAX_FILE_BYTES {
			return Err(Error::Limit);
		}
		let path = encode_path(path)?;
		self.with_wire(async move |wire| {
			let length = u64::try_from(output.len()).map_err(|_| Error::Limit)?;
			let source = Source::open(wire, path, Extent::Exact(length)).await?;
			let mut range = ReadRange::new(0, length, source.before.length)?;
			let mut remaining = output;
			while !remaining.is_empty() {
				let limit = remaining.len().min(MAX_READ_CHUNK_BYTES);
				let count = range
					.read_into(wire, &source.file, &mut remaining[..limit])
					.await?;
				remaining = &mut remaining[count..];
			}
			range.require_complete()?;
			source.finish(wire).await
		})
		.await
	}

	async fn open_source(
		&mut self,
		path: SftpString,
		extent: Extent,
		deadline: Instant,
	) -> Result<(Session, Source), Error> {
		let mut session = self.session.take().ok_or(Error::Closed)?;
		let source = session
			.run(deadline, async move |wire| {
				Source::open(wire, path, extent).await
			})
			.await?;
		Ok((session, source))
	}
}

impl RemoteReadFile<'_> {
	/// Returns the server-reported observation captured when the stream opened.
	#[must_use]
	pub const fn observation(&self) -> FileObservation {
		self.source.before
	}

	/// Reads the next chunk, advancing the stream cursor by the returned count.
	///
	/// The buffer length must be between 1 and 32 KiB. A positive short read
	/// advances by the returned count. Zero means the captured extent has been
	/// consumed. The caller must finish the stream to check EOF and metadata.
	///
	/// # Errors
	/// Invalid buffer size, early EOF, limits, or transport failures fence the session.
	/// Discard any buffer contents from a failed call.
	pub async fn read_next(&mut self, output: &mut [u8]) -> Result<usize, Error> {
		let mut session = self.session.take().ok_or(Error::Closed)?;
		let read = session
			.run(self.deadline, async |wire| {
				self.range.read_into(wire, &self.source.file, output).await
			})
			.await?;
		self.session = Some(session);
		Ok(read)
	}

	/// Verifies EOF, rechecks the held observation, closes the handle, and
	/// rechecks the named observation before releasing the session.
	///
	/// # Errors
	/// Refuses incomplete consumption, changed source observations, expiry, or any
	/// operation failure. A failure fences the session.
	pub async fn finish(self) -> Result<FileObservation, Error> {
		let mut session = self.session.ok_or(Error::Closed)?;
		let source = session
			.run(self.deadline, async move |wire| {
				self.range.require_complete()?;
				self.source.finish(wire).await
			})
			.await?;
		*self.parent = Some(session);
		Ok(source)
	}
}

struct Source {
	path: SftpString,
	file: SftpHandle,
	before: FileObservation,
}

enum Extent {
	Sequential,
	Exact(u64),
	Positioned,
}

impl Source {
	async fn open(wire: &mut Wire, path: SftpString, extent: Extent) -> Result<Self, Error> {
		let before = lstat(wire, path.clone()).await?;
		match extent {
			Extent::Sequential if before.length > MAX_STREAM_BYTES => return Err(Error::Limit),
			Extent::Exact(expected) if before.length != expected => return Err(Error::Changed),
			_ => {}
		}
		let file = handle(
			wire.request(|id| {
				Open {
					id,
					filename: path.clone(),
					pflags: OpenFlags::READ,
					attrs: FileAttributes::empty(),
				}
				.into()
			})
			.await?,
		)?;
		let source = Self { path, file, before };
		source.recheck_handle(wire).await?;
		Ok(source)
	}

	async fn recheck(&self, wire: &mut Wire) -> Result<(), Error> {
		self.recheck_handle(wire).await?;
		Self::recheck_name(wire, self.path.clone(), self.before).await
	}

	async fn recheck_handle(&self, wire: &mut Wire) -> Result<(), Error> {
		if fstat(wire, &self.file).await? != self.before {
			return Err(Error::Changed);
		}
		Ok(())
	}

	async fn recheck_name(
		wire: &mut Wire,
		path: SftpString,
		before: FileObservation,
	) -> Result<(), Error> {
		if lstat(wire, path).await? != before {
			return Err(Error::Changed);
		}
		Ok(())
	}

	async fn finish(self, wire: &mut Wire) -> Result<FileObservation, Error> {
		match read(wire, &self.file, self.before.length, 1).await? {
			Packet::Status(status) if status.status_code == StatusCode::Eof => {}
			Packet::Data(_) => return Err(Error::Changed),
			response => return Err(unexpected(response)),
		}
		self.recheck_handle(wire).await?;
		close(wire, self.file).await?;
		Self::recheck_name(wire, self.path, self.before).await?;
		Ok(self.before)
	}
}

async fn fstat(wire: &mut Wire, file: &SftpHandle) -> Result<FileObservation, Error> {
	observation(
		wire.request(|id| {
			Fstat {
				id,
				handle: file.clone(),
			}
			.into()
		})
		.await?,
	)
}

async fn read(wire: &mut Wire, file: &SftpHandle, offset: u64, len: u32) -> Result<Packet, Error> {
	wire.request(|id| {
		Read {
			id,
			handle: file.clone(),
			offset,
			len,
		}
		.into()
	})
	.await
}
