//! Capability-scoped operating-system adapters for ExaCopy.
#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]
#![cfg_attr(target_os = "macos", deny(unsafe_code))]

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod windows;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "../tests/common/scratch.rs"]
mod scratch;
