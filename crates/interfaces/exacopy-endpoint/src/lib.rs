//! Bounded operation contracts shared by storage adapters.
#![forbid(unsafe_code)]

pub mod connection_retry;
mod journal_segment;
pub mod linux_apply;
pub mod linux_copy;
pub mod linux_job;
pub mod linux_publication;
pub mod linux_recovery;
pub mod linux_remote_qualification;
pub mod linux_staging;
pub mod plan_bundle;
mod positioned;
mod read_view;
pub mod remote_source;
pub mod ssh_sftp;
mod staging;
pub mod wireguard;

#[cfg(kani)]
#[path = "../verification/kani/mod.rs"]
mod kani_checks;

pub use exacopy_core::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
pub use journal_segment::{JournalFileBarrier, JournalSegment};
pub use positioned::{
	IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES, read_exact_at, write_all_at,
};
pub use read_view::ReadView;
pub use staging::{ClosedStage, FreshStage, MetadataSource, RequiredMetadataStage};
