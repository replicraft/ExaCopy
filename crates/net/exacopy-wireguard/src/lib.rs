//! A bounded, experimental BoringTun protocol adapter.
#![forbid(unsafe_code)]

#[cfg(all(
	feature = "experimental-protocol",
	any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub mod protocol;

#[cfg(all(
	feature = "experimental-udp",
	any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub mod udp;

#[cfg(all(
	feature = "experimental-tcp",
	any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub mod stack;
