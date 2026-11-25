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

pub use connection::{Ed25519Key, Password, connect, connect_with_ed25519};
pub use data::{FileObservation, ReadOnlySftp};
pub use error::Error;
pub use known_hosts::{KnownHostTrust, KnownHostsError};
