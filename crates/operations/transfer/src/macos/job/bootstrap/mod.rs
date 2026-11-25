//! Synchronized preparation policy for an exclusively created, leased private job.

mod capabilities;
mod engine;

#[cfg(test)]
mod tests;

pub use capabilities::{PrivateJob, PrivateJournalDirectory};
pub use engine::{BootstrapError, JobPreparation, prepare};
