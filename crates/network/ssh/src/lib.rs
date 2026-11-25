//! Direct read-only SFTP v3 prototype over a caller-provided SSH stream.
#![forbid(unsafe_code)]
#![cfg(feature = "experimental-ssh")]

mod connection;
mod data;
mod error;
mod fence;
mod shape;
mod wire;

pub use connection::{Password, connect};
pub use data::{FileObservation, ReadOnlySftp};
pub use error::Error;
