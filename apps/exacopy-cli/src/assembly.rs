//! Concrete native capability wiring for the CLI application.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
pub mod macos;

#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
pub(crate) mod ssh_session;

#[cfg(all(
	feature = "experimental-ssh-capture",
	any(target_os = "linux", target_os = "macos")
))]
pub mod remote_ssh;
