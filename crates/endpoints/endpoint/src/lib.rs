//! Bounded operation contracts shared by storage adapters.
#![forbid(unsafe_code)]

mod component;
mod positioned;

pub use component::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
pub use positioned::{
	IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES, read_exact_at, write_all_at,
};
