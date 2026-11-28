//! ExaCopy CLI composition and command dispatch, shared with its integration tests.
#![forbid(unsafe_code)]

pub mod assembly;

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
mod apfs_inspect;
mod args;
mod command;
#[cfg(target_os = "linux")]
mod copy;
mod copy_report;
#[cfg(any(
	target_os = "linux",
	target_os = "macos",
	all(target_os = "windows", feature = "experimental-windows-diff")
))]
mod diff;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod linux_path;
#[cfg(target_os = "macos")]
mod macos;
mod manifest;
mod manifest_report;
mod plan;
#[cfg(target_os = "linux")]
mod profile;
#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
mod public_stage_inspect;
#[cfg(target_os = "linux")]
mod recovery;
mod recovery_report;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
mod remote;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
mod remote_frontdoor;
#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
mod remote_inspect_witness;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
mod remote_report;
mod report;
mod sync_preview;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_path;
#[cfg(all(target_os = "windows", feature = "experimental-windows-diff"))]
mod windows;
#[cfg(all(
	target_os = "windows",
	feature = "experimental-windows-bootstrap-inspect"
))]
mod windows_bootstrap_inspect;
#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
mod witness_archive;

pub use command::run;
