//! Bounded, read-only byte comparison over held local file views.
#![forbid(unsafe_code)]

#[cfg(any(target_os = "linux", test))]
mod compare;
#[cfg(target_os = "linux")]
pub mod linux;
