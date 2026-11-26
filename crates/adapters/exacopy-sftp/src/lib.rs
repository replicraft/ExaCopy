//! Held remote-source adapter over an application-owned authenticated SFTP session.
#![forbid(unsafe_code)]
#![cfg(feature = "experimental-sftp")]

mod error;
mod source;

pub use error::SftpSourceError;
pub use source::{
	PendingSftpPathRequest, PendingSftpSource, PendingSftpSourceRequest, PendingSourceOwner,
	open_pending_path_source, open_pending_source, with_pending_source,
};
pub use source::{SftpSource, SftpSourceRequest, with_source};
