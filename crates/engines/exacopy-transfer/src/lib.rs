//! Preserve-mode file transfer coordination.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod copy_planning;

#[cfg(target_os = "linux")]
pub mod manifest;
#[cfg(target_os = "linux")]
pub mod public_plan;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod linux_staging;

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
pub mod macos;

pub mod staging;

pub mod remote_capture;

pub mod remote_resume;
