//! Concrete native capability wiring for the CLI application.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
pub mod macos;
