use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_endpoint::wireguard::{InnerDial, InnerDialKind};
use minicbor::encode::{self, Write, write::Cursor};
use minicbor::{Decoder, Encoder};

use crate::{JournalEntryId, LinuxFileIdentity, RootCapabilityId, StreamLength};

use super::RemoteDownloadError as Error;
use super::wire::{array, fixed, key, map, read_identity, write_identity};

/// Maximum raw account-relative SFTP path bytes including separators.
pub const MAX_REMOTE_PATH_BYTES: usize = 4096;
const SCOPE_DOMAIN: &[u8] = b"ExaCopy/linux-remote-scope/v1\0";
const DIRECT: u8 = 0;
const EMBEDDED: u8 = 1;
const PROCESS_CRASH: u8 = 0;

pub(super) const MAX_BODY_BYTES: usize = 6144;

/// The canonical remote scope's independent, domain-separated digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteScopeDigest([u8; 32]);

impl RemoteScopeDigest {
	/// Wraps recorded digest bytes for comparison against authenticated scope.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the exact digest bytes.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Immutable route selection that requires fresh admission before connecting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteDownloadRoute {
	/// Explicitly selected direct SSH.
	Direct,
	/// SSH through the exact independently approved embedded route revision.
	EmbeddedWireGuard {
		/// Public reference to the selected embedded peer.
		peer: [u8; 32],
		/// Digest of the approved route revision.
		revision: [u8; 32],
		/// Literal inner SSH destination for the selected peer.
		inner: SocketAddr,
	},
}

/// Validated authority, pinned host key, route and exact relative source name.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteDownloadSource {
	authority: SshAuthority,
	host_key_sha256: [u8; 32],
	route: RemoteDownloadRoute,
	path: Box<[u8]>,
}

impl RemoteDownloadSource {
	/// Binds one ordinary account-relative path using the exact endpoint syntax.
	/// # Errors
	/// Refuses invalid route references, route target, empty key or unbounded name.
	pub fn new(
		authority: SshAuthority,
		host_key_sha256: [u8; 32],
		route: RemoteDownloadRoute,
		path: &[u8],
	) -> Result<Self, Error> {
		if path.len() > MAX_REMOTE_PATH_BYTES {
			return Err(Error::Length);
		}
		if host_key_sha256 == [0; 32]
			|| path
				.split(|byte| *byte == b'/')
				.any(|name| UnixComponent::new(name).is_err())
		{
			return Err(Error::Scope);
		}
		if let RemoteDownloadRoute::EmbeddedWireGuard {
			peer,
			revision,
			inner,
		} = route
			&& (peer == [0; 32]
				|| revision == [0; 32]
				|| inner.port() != authority.port().get()
				|| InnerDial::new(InnerDialKind::Stream, inner).is_none())
		{
			return Err(Error::Scope);
		}
		Ok(Self {
			authority,
			host_key_sha256,
			route,
			path: path.into(),
		})
	}

	/// Returns the canonical host, port and account.
	#[must_use]
	pub const fn authority(&self) -> &SshAuthority {
		&self.authority
	}

	/// Returns the approved SSH host-key fingerprint bytes.
	#[must_use]
	pub const fn host_key_sha256(&self) -> &[u8; 32] {
		&self.host_key_sha256
	}

	/// Returns the selected route declaration.
	#[must_use]
	pub const fn route(&self) -> RemoteDownloadRoute {
		self.route
	}

	/// Returns the exact validated account-relative path.
	#[must_use]
	pub fn path(&self) -> &[u8] {
		&self.path
	}
}

impl fmt::Debug for RemoteDownloadSource {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RemoteDownloadSource")
			.finish_non_exhaustive()
	}
}

/// Held local destination declaration with one validated basename.
#[derive(Clone, Eq, PartialEq)]
pub struct RemoteDownloadDestination {
	root: RootCapabilityId,
	parent: LinuxFileIdentity,
	target: Box<[u8]>,
}

impl RemoteDownloadDestination {
	/// Records the local root alias, native parent identity and target component.
	#[must_use]
	pub fn new(
		root: RootCapabilityId,
		parent: LinuxFileIdentity,
		target: UnixComponent<'_>,
	) -> Self {
		Self {
			root,
			parent,
			target: target.as_bytes().into(),
		}
	}

	/// Returns the declared local root alias.
	#[must_use]
	pub const fn root(&self) -> RootCapabilityId {
		self.root
	}

	/// Returns the recorded local parent identity.
	#[must_use]
	pub const fn parent(&self) -> LinuxFileIdentity {
		self.parent
	}

	/// Returns the exact validated local basename.
	#[must_use]
	pub fn target(&self) -> &[u8] {
		&self.target
	}
}

impl fmt::Debug for RemoteDownloadDestination {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RemoteDownloadDestination")
			.field("parent", &self.parent)
			.finish_non_exhaustive()
	}
}

/// Requested semantics, subject to independently qualified local operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteDownloadDurability {
	/// The caller requests a process-crash durability profile.
	ProcessCrash,
}

/// Immutable single-entry preserve-mode capture scope.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RemoteDownloadScope {
	/// Private entry identifier in the single-entry job.
	pub entry: JournalEntryId,
	/// Selected live SFTP endpoint and raw path.
	pub source: RemoteDownloadSource,
	/// Selected local destination.
	pub destination: RemoteDownloadDestination,
	/// Signed maximum authorized source extent.
	pub maximum_extent: StreamLength,
	/// Digest of the chosen local metadata policy.
	pub metadata_policy: [u8; 32],
	/// Requested local durability level.
	pub requested_durability: RemoteDownloadDurability,
}

impl RemoteDownloadScope {
	/// Constructs a scope declaration with a nonnil private entry.
	/// # Errors
	/// Refuses a nil entry identifier.
	pub fn new(
		entry: JournalEntryId,
		source: RemoteDownloadSource,
		destination: RemoteDownloadDestination,
		maximum_extent: StreamLength,
		metadata_policy: [u8; 32],
		requested_durability: RemoteDownloadDurability,
	) -> Result<Self, Error> {
		let scope = Self {
			entry,
			source,
			destination,
			maximum_extent,
			metadata_policy,
			requested_durability,
		};
		scope.validate()?;
		Ok(scope)
	}

	/// Measures the canonical immutable scope under its separate digest domain.
	/// # Errors
	/// Refuses invalid scopes and data exceeding the owner encoding bound.
	pub fn digest(&self) -> Result<RemoteScopeDigest, Error> {
		self.validate()?;
		let mut encoder = Encoder::new(Cursor::new([0; MAX_BODY_BYTES]));
		self.write(&mut encoder)?;
		let encoded = encoder.into_writer();
		let mut hash = blake3::Hasher::new();
		hash.update(SCOPE_DOMAIN);
		hash.update(&encoded.get_ref()[..encoded.position()]);
		Ok(RemoteScopeDigest::from_bytes(*hash.finalize().as_bytes()))
	}

	pub(super) fn validate(&self) -> Result<(), Error> {
		(self.entry.as_bytes() != &[0; 16])
			.then_some(())
			.ok_or(Error::Binding)
	}

	pub(super) fn read(decoder: &mut Decoder<'_>) -> Result<Self, Error> {
		map(decoder, 4)?;
		key(decoder, 0)?;
		let entry = JournalEntryId::from_bytes(fixed(decoder)?);
		key(decoder, 1)?;
		let source = read_source(decoder)?;
		key(decoder, 2)?;
		array(decoder, 3)?;
		let root = RootCapabilityId::from_bytes(fixed(decoder)?).map_err(|_| Error::Binding)?;
		let parent = read_identity(decoder)?;
		let target = UnixComponent::new(decoder.bytes()?).map_err(|_| Error::Scope)?;
		let destination = RemoteDownloadDestination::new(root, parent, target);
		key(decoder, 3)?;
		array(decoder, 3)?;
		let maximum_extent = StreamLength::new(decoder.u64()?).map_err(|_| Error::Binding)?;
		let metadata_policy = fixed(decoder)?;
		let requested_durability = match decoder.u8()? {
			PROCESS_CRASH => RemoteDownloadDurability::ProcessCrash,
			_ => return Err(Error::Scope),
		};
		Self::new(
			entry,
			source,
			destination,
			maximum_extent,
			metadata_policy,
			requested_durability,
		)
	}

	pub(super) fn write<W: Write>(
		&self,
		out: &mut Encoder<W>,
	) -> Result<(), encode::Error<W::Error>> {
		let source = &self.source;
		let destination = &self.destination;
		out.map(4)?
			.u8(0)?
			.bytes(self.entry.as_bytes())?
			.u8(1)?
			.array(4)?
			.array(3)?
			.str(source.authority.host())?
			.u16(source.authority.port().get())?
			.str(source.authority.account())?
			.bytes(&source.host_key_sha256)?;
		write_route(out, source.route)?;
		out.bytes(&source.path)?
			.u8(2)?
			.array(3)?
			.bytes(destination.root.as_bytes())?;
		write_identity(out, destination.parent)?;
		let durability = match self.requested_durability {
			RemoteDownloadDurability::ProcessCrash => PROCESS_CRASH,
		};
		out.bytes(&destination.target)?
			.u8(3)?
			.array(3)?
			.u64(self.maximum_extent.get())?
			.bytes(&self.metadata_policy)?
			.u8(durability)?;
		Ok(())
	}
}

fn read_source(decoder: &mut Decoder<'_>) -> Result<RemoteDownloadSource, Error> {
	array(decoder, 4)?;
	array(decoder, 3)?;
	let host = decoder.str()?;
	let port = NonZeroU16::new(decoder.u16()?).ok_or(Error::Scope)?;
	let account = decoder.str()?;
	let authority = SshAuthority::new(host, port, account).map_err(|_| Error::Scope)?;
	let host_key = fixed(decoder)?;
	let route = read_route(decoder)?;
	RemoteDownloadSource::new(authority, host_key, route, decoder.bytes()?)
}

fn read_route(decoder: &mut Decoder<'_>) -> Result<RemoteDownloadRoute, Error> {
	match (decoder.array()?, decoder.u8()?) {
		(Some(1), DIRECT) => Ok(RemoteDownloadRoute::Direct),
		(Some(5), EMBEDDED) => {
			let peer = fixed(decoder)?;
			let revision = fixed(decoder)?;
			let address = decoder.bytes()?;
			let ip = match address.len() {
				4 => IpAddr::from(<[u8; 4]>::try_from(address).map_err(|_| Error::Scope)?),
				16 => IpAddr::from(<[u8; 16]>::try_from(address).map_err(|_| Error::Scope)?),
				_ => return Err(Error::Scope),
			};
			let inner = SocketAddr::new(ip, decoder.u16()?);
			Ok(RemoteDownloadRoute::EmbeddedWireGuard {
				peer,
				revision,
				inner,
			})
		}
		_ => Err(Error::Scope),
	}
}

fn write_route<W: Write>(
	out: &mut Encoder<W>,
	route: RemoteDownloadRoute,
) -> Result<(), encode::Error<W::Error>> {
	match route {
		RemoteDownloadRoute::Direct => {
			out.array(1)?.u8(DIRECT)?;
		}
		RemoteDownloadRoute::EmbeddedWireGuard {
			peer,
			revision,
			inner,
		} => {
			out.array(5)?.u8(EMBEDDED)?.bytes(&peer)?.bytes(&revision)?;
			match inner.ip() {
				IpAddr::V4(ip) => {
					out.bytes(&ip.octets())?;
				}
				IpAddr::V6(ip) => {
					out.bytes(&ip.octets())?;
				}
			}
			out.u16(inner.port())?;
		}
	}
	Ok(())
}
