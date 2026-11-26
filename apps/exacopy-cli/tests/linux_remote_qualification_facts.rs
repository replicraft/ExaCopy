//! Integration entry point for the native remote qualification observation fixture.

#[cfg(target_os = "linux")]
#[path = "../verification/remote/native_facts.rs"]
mod native_facts;
