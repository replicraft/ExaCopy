//! Bounded, read-only byte comparison over held local file views.
#![forbid(unsafe_code)]

mod compare;

pub use compare::error::{CompareError, Side};
pub use compare::parallel::{MAX_WORKERS, compare_parallel};
pub use compare::{Difference, LiveComparison, MAX_SCRATCH_BYTES, compare};
