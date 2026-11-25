//! Bounded, versioned journal framing and chain checks for local recovery.

#![forbid(unsafe_code)]

mod durable;
pub mod frame;

pub use durable::{DurableJournal, DurableJournalError, SyncedFrame};
