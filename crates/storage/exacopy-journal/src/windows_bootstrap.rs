//! Historical storage evidence for the selected Windows fixed-NTFS first segment.

mod codec;
mod error;
mod identity;
mod inspect;
mod names;
mod record;

pub use error::{
	WindowsBootstrapEncodeError, WindowsBootstrapIdentityError, WindowsBootstrapInspectionError,
	WindowsBootstrapOwnerError,
};
pub use identity::{WindowsBootstrapFileIdentity, WindowsBootstrapRoles};
pub use inspect::{
	WindowsBootstrapEvidence, WindowsBootstrapPrefix, WindowsBootstrapSelection, inspect,
};
pub use names::{FIRST_SEGMENT_NAME, JOURNAL_DIRECTORY_NAME, OWNER_FILE_NAME, job_directory_name};
pub use record::{
	FIRST_SEGMENT_BYTES, OWNER_BYTES, PREPARED_BYTES, WindowsBootstrapBytes, WindowsBootstrapOwner,
	sign,
};
