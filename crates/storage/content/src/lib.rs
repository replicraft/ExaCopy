//! Bounded measurement of one logical file stream.
#![forbid(unsafe_code)]

mod checkpoint;
mod digest;
mod error;
mod stream;

pub use checkpoint::{RangeMeasurement, copy_and_checkpoint_at};
pub use digest::ContentDigest;
pub use error::{CopyMeasureError, MeasureError, StreamInputError};
pub use stream::{MAX_SCRATCH_BYTES, copy_and_measure_at, measure_at, validate_stream_input};
