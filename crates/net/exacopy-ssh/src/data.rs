use std::collections::BTreeSet;
use std::pin::Pin;
use std::time::Duration;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::remote_source::{SftpPath, SftpPathRoot};
use exacopy_endpoint::ssh_sftp::SftpCapabilities;
use russh_sftp::protocol::{
	Close, Lstat, OpenDir, Packet, ReadDir, SftpHandle, SftpString, StatusCode,
};
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::DropGuard;

use crate::connection::SshAuthenticatedPeer;
use crate::error::Error;
use crate::fence::SshSessionCancellation;
use crate::wire::Wire;

mod source;

pub use source::{
	MAX_READ_CHUNK_BYTES, MAX_STREAM_BYTES, RemotePositionedRead, RemoteReadFile, RemoteReadWindow,
	WindowObservation,
};

const OPERATION_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PATH_BYTES: usize = 4096;
const MAX_BATCHES: usize = 128;
const MAX_ENTRIES: usize = 4096;
const MAX_HANDLE_BYTES: usize = 256;
const TYPE_MASK: u32 = 0o170000;
const REGULAR: u32 = 0o100000;

/// Selected fields observed through SFTP v3; values are server-reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileObservation {
	/// Logical server-reported byte length.
	pub length: u64,
	/// The SFTP v3 mode field, including the file type.
	pub mode: u32,
	/// The modification timestamp in seconds.
	pub modified: u32,
}

/// A held, read-only SFTP v3 channel over an authenticated connection.
///
/// Paths are relative to the authenticated account's normal starting directory.
/// A name observation cannot guarantee server-side symlink confinement or
/// stable file identity. This is a read-only compatibility prototype.
pub struct ReadOnlySftp {
	session: Option<Session>,
	capabilities: SftpCapabilities,
	peer: SshAuthenticatedPeer,
	cancellation: SshSessionCancellation,
}

type SshConnection = Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>;

struct Session {
	wire: Wire,
	connection: SshConnection,
	disconnect: oneshot::Sender<oneshot::Sender<()>>,
	_guard: DropGuard,
}

impl ReadOnlySftp {
	pub(crate) fn new(
		wire: Wire,
		connection: SshConnection,
		guard: DropGuard,
		peer: SshAuthenticatedPeer,
		cancellation: SshSessionCancellation,
		disconnect: oneshot::Sender<oneshot::Sender<()>>,
	) -> Self {
		Self {
			capabilities: wire.capabilities,
			peer,
			cancellation,
			session: Some(Session {
				wire,
				connection,
				disconnect,
				_guard: guard,
			}),
		}
	}

	/// Returns the host key and authority verified for this session's login.
	#[must_use]
	pub const fn authenticated_peer(&self) -> &SshAuthenticatedPeer {
		&self.peer
	}

	/// Returns a cancel-only capability tied to this exact session's transport.
	#[must_use]
	pub fn cancellation_handle(&self) -> SshSessionCancellation {
		self.cancellation.clone()
	}

	/// Requests a protocol disconnect and observes the underlying write shutdown.
	///
	/// This consumes the session and cannot return further source bytes. The
	/// route owner still defines and confirms its own transport retirement.
	///
	/// # Errors
	/// Refuses an unavailable session, failed shutdown, or a deadline reached
	/// before its completion. Dropping the wait fences the owning stream.
	pub async fn disconnect_before(mut self, deadline: Instant) -> Result<(), Error> {
		let Session {
			disconnect,
			connection,
			_guard,
			wire: _wire,
		} = self.session.take().ok_or(Error::Closed)?;
		if Instant::now() >= deadline {
			return Err(Error::Timeout);
		}
		let result = timeout_at(deadline, async {
			let (accepted, observed) = oneshot::channel();
			disconnect.send(accepted).map_err(|_| Error::Closed)?;
			observed.await.map_err(|_| Error::Closed)?;
			match connection.await {
				// Russh projects a locally requested disconnect as the generic
				// Disconnect error. Neither that result nor a queue acceptance
				// confirms shutdown without the exact stream observation.
				Ok(()) | Err(Error::Ssh(russh::Error::Disconnect))
					if self.cancellation.shutdown_confirmed() =>
				{
					Ok(())
				}
				Ok(()) => Err(Error::Closed),
				Err(error) => Err(error),
			}
		})
		.await
		.map_err(|_| Error::Timeout)?;
		if Instant::now() >= deadline {
			return Err(Error::Timeout);
		}
		result
	}

	/// Returns protocol support and extension advertisements.
	#[must_use]
	pub const fn capabilities(&self) -> SftpCapabilities {
		self.capabilities
	}

	/// Observes a selected regular source through SFTP LSTAT.
	///
	/// # Errors
	/// Fails on unsupported source kind, incomplete metadata, or transport failure.
	pub async fn stat(&mut self, path: &[UnixComponent<'_>]) -> Result<FileObservation, Error> {
		let path = encode_path(path)?;
		self.with_wire(async move |wire| lstat(wire, path).await)
			.await
	}

	/// Completes one bounded directory listing, preserving exact filename bytes.
	///
	/// # Errors
	/// Fails on malformed names, duplicate entries, or an incomplete listing.
	pub async fn list(&mut self, path: &[UnixComponent<'_>]) -> Result<Vec<Vec<u8>>, Error> {
		let path = encode_path(path)?;
		self.with_wire(async move |wire| list(wire, path).await)
			.await
	}

	async fn with_wire<T>(
		&mut self,
		operation: impl AsyncFnOnce(&mut Wire) -> Result<T, Error>,
	) -> Result<T, Error> {
		// Taking ownership fences the route on cancellation or failure.
		let mut session = self.session.take().ok_or(Error::Closed)?;
		let value = session
			.run(Instant::now() + OPERATION_TIMEOUT, operation)
			.await?;
		self.session = Some(session);
		Ok(value)
	}
}

impl Session {
	async fn run<T>(
		&mut self,
		deadline: Instant,
		operation: impl AsyncFnOnce(&mut Wire) -> Result<T, Error>,
	) -> Result<T, Error> {
		if Instant::now() >= deadline {
			return Err(Error::Timeout);
		}
		let result = tokio::select! {
			biased;
			closed = &mut self.connection => return Err(closed.err().unwrap_or(Error::Closed)),
			result = timeout_at(deadline, operation(&mut self.wire)) => {
				result.map_err(|_| Error::Timeout)?
			}
		}?;
		if Instant::now() >= deadline {
			return Err(Error::Timeout);
		}
		Ok(result)
	}
}

fn encode_path(path: &[UnixComponent<'_>]) -> Result<SftpString, Error> {
	encode_selected_path(SftpPath::AccountRelative(path))
}

fn encode_selected_path(path: SftpPath<'_>) -> Result<SftpString, Error> {
	let absolute = path.root() == SftpPathRoot::Absolute;
	let components = path.components();
	if components.is_empty() {
		return if absolute {
			Err(Error::UnsupportedSource)
		} else {
			Ok(SftpString::from("."))
		};
	}
	let mut bytes = Vec::new();
	for (index, component) in components.iter().enumerate() {
		let name = component.as_bytes();
		let separator = usize::from(absolute || index != 0);
		if bytes.len() + separator + name.len() > MAX_PATH_BYTES {
			return Err(Error::Limit);
		}
		if separator != 0 {
			bytes.push(b'/');
		}
		bytes.extend_from_slice(name);
	}
	Ok(SftpString::from(bytes))
}

async fn list(wire: &mut Wire, path: SftpString) -> Result<Vec<Vec<u8>>, Error> {
	let directory = handle(wire.request(|id| OpenDir { id, path }.into()).await?)?;
	let mut entries = BTreeSet::new();
	for _ in 0..MAX_BATCHES {
		match wire
			.request(|id| {
				ReadDir {
					id,
					handle: directory.clone(),
				}
				.into()
			})
			.await?
		{
			Packet::Status(status) if status.status_code == StatusCode::Eof => {
				close(wire, directory).await?;
				return Ok(entries.into_iter().collect());
			}
			Packet::Name(names) if !names.files.is_empty() => {
				for entry in names.files {
					let name = entry.filename.into_bytes();
					if matches!(name.as_slice(), b"." | b"..") {
						continue;
					}
					UnixComponent::new(&name).map_err(|_| Error::Protocol)?;
					if entries.len() >= MAX_ENTRIES {
						return Err(Error::Limit);
					}
					if !entries.insert(name) {
						return Err(Error::Protocol);
					}
				}
			}
			response => return Err(unexpected(response)),
		}
	}
	Err(Error::Limit)
}

async fn lstat(wire: &mut Wire, path: SftpString) -> Result<FileObservation, Error> {
	observation(wire.request(|id| Lstat { id, path }.into()).await?)
}

fn observation(response: Packet) -> Result<FileObservation, Error> {
	let Packet::Attrs(reply) = response else {
		return Err(unexpected(response));
	};
	let mode = reply.attrs.permissions.ok_or(Error::UnsupportedSource)?;
	if mode & TYPE_MASK != REGULAR {
		return Err(Error::UnsupportedSource);
	}
	Ok(FileObservation {
		length: reply.attrs.size.ok_or(Error::UnsupportedSource)?,
		mode,
		modified: reply.attrs.mtime.ok_or(Error::UnsupportedSource)?,
	})
}

fn handle(response: Packet) -> Result<SftpHandle, Error> {
	match response {
		Packet::Handle(reply) if reply.handle.as_bytes().len() <= MAX_HANDLE_BYTES => {
			Ok(reply.handle)
		}
		Packet::Handle(_) => Err(Error::Limit),
		response => Err(unexpected(response)),
	}
}

async fn close(wire: &mut Wire, handle: SftpHandle) -> Result<(), Error> {
	match wire.request(|id| Close { id, handle }.into()).await? {
		Packet::Status(status) if status.status_code == StatusCode::Ok => Ok(()),
		response => Err(unexpected(response)),
	}
}

fn unexpected(response: Packet) -> Error {
	match response {
		Packet::Status(status) if status.status_code != StatusCode::Ok => {
			Error::Status(status.status_code)
		}
		_ => Error::Protocol,
	}
}
