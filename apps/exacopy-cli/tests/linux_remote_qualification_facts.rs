//! Integration entry point for the native remote qualification observation fixture.

#[cfg(target_os = "linux")]
#[path = "support/remote_qualification_facts.rs"]
mod native_facts;
