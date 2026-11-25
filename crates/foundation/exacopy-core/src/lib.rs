//! Pure domain primitives shared by ExaCopy libraries.
#![forbid(unsafe_code)]

mod component;
mod identity;

#[cfg(kani)]
#[path = "../verification/kani/mod.rs"]
mod kani_checks;

pub use component::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};
pub use identity::{EntryId, InvalidJobId, JobId, RunEpoch, StageId};
