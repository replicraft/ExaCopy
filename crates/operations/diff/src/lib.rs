//! Bounded, read-only byte comparison over held local file views.
#![forbid(unsafe_code)]

#[cfg(any(target_os = "linux", target_os = "macos", test))]
mod compare;
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use compare::error::{CompareError, Side};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use compare::parallel::MAX_WORKERS;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use compare::{Difference, LiveComparison, MAX_SCRATCH_BYTES};
