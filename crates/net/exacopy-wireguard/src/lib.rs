//! A bounded, experimental BoringTun protocol adapter.
#![forbid(unsafe_code)]

#[cfg(all(
	feature = "experimental-protocol",
	any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub mod protocol;
