//! Direct read-only SFTP v3 prototype over a caller-provided SSH stream.
#![forbid(unsafe_code)]
#![cfg(feature = "experimental-ssh")]

mod connection;
mod data;
mod error;
mod fence;
mod known_hosts;
mod shape;
mod wire;

pub use connection::MAX_OPENSSH_ED25519_BYTES;
pub use connection::{
	Ed25519Key, Password, SshAuthenticatedPeer, connect, connect_with_ed25519,
	connect_with_ed25519_async,
};
pub use data::{
	FileObservation, MAX_READ_CHUNK_BYTES, MAX_STREAM_BYTES, ReadOnlySftp, RemotePositionedRead,
	RemoteReadFile, RemoteReadWindow, WindowObservation,
};
pub use error::Error;
pub use fence::SshSessionCancellation;
pub use known_hosts::{KnownHostTrust, KnownHostsError};
