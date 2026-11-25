//! Capability-scoped operating-system adapters for ExaCopy.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux;
