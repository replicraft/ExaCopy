//! Capability-scoped operating-system adapters for ExaCopy.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux;

pub mod windows;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/common/scratch.rs"]
mod scratch;
