//! Qualification candidates for a Windows held directory and a read-only child.

#[cfg(target_os = "windows")]
#[path = "windows_read/cases.rs"]
mod cases;
#[path = "windows_read/directory_entries.rs"]
mod directory_entries;
#[cfg(target_os = "windows")]
#[path = "windows_read/native.rs"]
mod native;
