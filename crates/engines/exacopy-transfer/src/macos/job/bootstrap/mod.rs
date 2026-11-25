//! Synchronized preparation policy for an exclusively created, leased private job.

mod admission;
mod capabilities;
mod engine;

#[cfg(test)]
mod tests;

pub use admission::{
	BootstrapInputs, CreatedJob, JobCreationFailure, PrivateJobRoot, admit_and_create,
};
pub use capabilities::{PrivateJob, PrivateJournalDirectory};
pub use engine::{BootstrapError, JobPreparation, prepare};
