//! Capability-scoped operating-system adapters for ExaCopy.
#![cfg_attr(
	not(any(
		target_os = "macos",
		all(
			target_os = "linux",
			feature = "experimental-linux-managed-sync",
			target_pointer_width = "64",
			any(target_arch = "x86_64", target_arch = "aarch64")
		),
		all(
			target_os = "windows",
			any(
				feature = "experimental-windows-copy",
				feature = "experimental-windows-read"
			)
		)
	)),
	forbid(unsafe_code)
)]
#![cfg_attr(
	any(
		target_os = "macos",
		all(
			target_os = "linux",
			feature = "experimental-linux-managed-sync",
			target_pointer_width = "64",
			any(target_arch = "x86_64", target_arch = "aarch64")
		),
		all(
			target_os = "windows",
			any(
				feature = "experimental-windows-copy",
				feature = "experimental-windows-read"
			)
		)
	),
	deny(unsafe_code)
)]

#[cfg(target_os = "linux")]
#[forbid(unsafe_code)]
pub mod linux;

#[cfg(all(
	target_os = "linux",
	feature = "experimental-linux-managed-sync",
	target_pointer_width = "64",
	any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod managed_sync_statmount;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod windows;

mod protected_snapshot;

pub use protected_snapshot::{
	MAX_PROTECTED_SNAPSHOT_BYTES, ProtectedSnapshotError, read_protected_snapshot,
	read_protected_snapshot_into,
};

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "../tests/common/scratch.rs"]
mod scratch;
