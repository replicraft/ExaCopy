//! Preserve-mode file transfer coordination.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
pub mod macos;
