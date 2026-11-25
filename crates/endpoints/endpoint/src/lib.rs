//! Bounded operation contracts shared by storage adapters.
#![forbid(unsafe_code)]

mod component;
pub mod linux_copy;
pub mod linux_job;
pub mod linux_publication;
pub mod linux_recovery;
pub mod linux_staging;
mod positioned;
mod read_view;
pub mod ssh_sftp;
mod staging;
pub mod wireguard;

#[cfg(kani)]
#[path = "../verification/kani/mod.rs"]
mod kani_checks;

pub use component::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
pub use positioned::{
	IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES, read_exact_at, write_all_at,
};
pub use read_view::ReadView;
pub use staging::{ClosedStage, FreshStage, MetadataSource, RequiredMetadataStage};
