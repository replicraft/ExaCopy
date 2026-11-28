//! Checks for the real checked local-apply grant policy.

#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
mod local_apply;
