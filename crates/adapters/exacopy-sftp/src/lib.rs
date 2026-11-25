//! Held remote-source adapter over an application-owned authenticated SFTP session.
#![forbid(unsafe_code)]
#![cfg(feature = "experimental-sftp")]

mod error;
mod source;

pub use error::SftpSourceError;
pub use source::{SftpSource, SftpSourceRequest, with_source};
