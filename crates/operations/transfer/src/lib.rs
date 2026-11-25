//! Preserve-mode file transfer coordination.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod linux_staging;

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
pub mod macos;

#[cfg(any(
	target_os = "linux",
	all(target_os = "macos", feature = "experimental-apfs-copy")
))]
pub mod staging;
