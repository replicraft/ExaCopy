use exacopy_platform::linux::{ReadError, StageError};

use crate::linux_staging;

/// A failed Linux private staging attempt at its last observed model phase.
pub type StageCopyError = linux_staging::StageCopyError<ReadError, StageError>;

/// The typed cause of a Linux private staging failure.
pub type StageFailure = linux_staging::StageFailure<ReadError, StageError>;
