use std::error::Error;
use std::fmt;

use exacopy_content::{ContentDigest, CopyMeasureError, MeasureError, StreamInputError};
use exacopy_platform::macos::ManagedReadError;
use exacopy_platform::macos::staging::{MAX_STAGE_IO_BYTES, StageError, StageIdentity};

use exacopy_transfer::staging::StageCopyFailure;

/// A failed private transfer and the identity of its retained stage.
#[derive(Debug)]
pub struct StageTransferError {
	identity: StageIdentity,
	failure: Box<StageTransferFailure>,
}

impl StageTransferError {
	pub(super) fn from_copy(
		identity: StageIdentity,
		failure: StageCopyFailure<ManagedReadError, StageError>,
	) -> Self {
		Self {
			identity,
			failure: Box::new(StageTransferFailure::from_copy(failure)),
		}
	}

	/// Returns the identity allocated before creating the retained private stage.
	#[must_use]
	pub fn identity(&self) -> StageIdentity {
		self.identity
	}

	/// Returns the typed phase and cause of the failure.
	#[must_use]
	pub fn failure(&self) -> &StageTransferFailure {
		&self.failure
	}
}

impl fmt::Display for StageTransferError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.failure.fmt(formatter)
	}
}

impl Error for StageTransferError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(self.failure.as_ref())
	}
}

/// Admission, source, stage or verification failure during a private transfer.
#[derive(Debug)]
#[non_exhaustive]
pub enum StageTransferFailure {
	/// The stage writer could not be admitted as fresh.
	InitialStage(StageError),
	/// The captured source length differs from the stage's declared extent.
	ExtentMismatch {
		/// Captured source length in bytes.
		source_length: u64,
		/// Declared stage length in bytes.
		stage_length: u64,
	},
	/// Scratch is larger than the native stage I/O limit.
	ScratchTooLarge {
		/// Supplied buffer length in bytes.
		length: usize,
	},
	/// Stream length or scratch failed baseline stream validation.
	InvalidInput(StreamInputError),
	/// The source could not be revalidated before or after the transfer.
	RevalidateSource(ManagedReadError),
	/// The source did not satisfy the strict metadata profile before transfer.
	AdmitMetadata(ManagedReadError),
	/// The verified stage could not install and synchronize the required metadata.
	ApplyMetadata(StageError),
	/// A source read or private write could not complete.
	Copy(CopyMeasureError<ManagedReadError, StageError>),
	/// The stage could not complete the barrier and confirmed writer closure.
	CloseStage(StageError),
	/// The independent read-only descriptor could not be opened.
	OpenReadBack(StageError),
	/// The independent read-back did not complete.
	ReadBack(MeasureError<StageError>),
	/// The reader could not confirm the same private stage at its logical EOF.
	RevalidateReadBack(StageError),
	/// The complete source stream and independent read-back measured different digests.
	DigestMismatch {
		/// Digest computed from bytes supplied by the source reader.
		source_digest: ContentDigest,
		/// Digest computed independently from the private stage.
		stage_digest: ContentDigest,
	},
}

impl StageTransferFailure {
	pub(super) fn from_copy(failure: StageCopyFailure<ManagedReadError, StageError>) -> Self {
		match failure {
			StageCopyFailure::InitialStage(error) => Self::InitialStage(error),
			StageCopyFailure::ExtentMismatch {
				source_length,
				stage_length,
			} => Self::ExtentMismatch {
				source_length,
				stage_length,
			},
			StageCopyFailure::ScratchTooLarge { length } => Self::ScratchTooLarge { length },
			StageCopyFailure::InvalidInput(error) => Self::InvalidInput(error),
			StageCopyFailure::RevalidateSource(error) => Self::RevalidateSource(error),
			StageCopyFailure::AdmitMetadata(error) => Self::AdmitMetadata(error),
			StageCopyFailure::ApplyMetadata(error) => Self::ApplyMetadata(error),
			StageCopyFailure::Copy(error) => Self::Copy(error),
			StageCopyFailure::CloseStage(error) => Self::CloseStage(error),
			StageCopyFailure::OpenReadBack(error) => Self::OpenReadBack(error),
			// A native reader for the held stage must observe its declared extent.
			StageCopyFailure::ReadBackExtentMismatch { .. } => {
				Self::OpenReadBack(StageError::StageChanged)
			}
			StageCopyFailure::ReadBack(error) => Self::ReadBack(error),
			StageCopyFailure::RevalidateReadBack(error) => Self::RevalidateReadBack(error),
			StageCopyFailure::DigestMismatch {
				source_digest,
				stage_digest,
			} => Self::DigestMismatch {
				source_digest,
				stage_digest,
			},
		}
	}
}

impl fmt::Display for StageTransferFailure {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InitialStage(error) => write!(formatter, "stage admission failed ({error})"),
			Self::ExtentMismatch {
				source_length,
				stage_length,
			} => write!(
				formatter,
				"source extent {source_length} differs from stage extent {stage_length}"
			),
			Self::ScratchTooLarge { length } => write!(
				formatter,
				"scratch length {length} exceeds the {MAX_STAGE_IO_BYTES}-byte stage limit"
			),
			Self::InvalidInput(error) => error.fmt(formatter),
			Self::RevalidateSource(error) => {
				write!(formatter, "source revalidation failed ({error})")
			}
			Self::AdmitMetadata(error) => write!(formatter, "source metadata refused ({error})"),
			Self::ApplyMetadata(error) => write!(formatter, "stage metadata failed ({error})"),
			Self::Copy(CopyMeasureError::Read { offset, source }) => write!(
				formatter,
				"source range beginning at byte {offset} could not be read: {source}"
			),
			Self::Copy(error) => error.fmt(formatter),
			Self::CloseStage(error) => {
				write!(formatter, "stage barrier or closure failed ({error})")
			}
			Self::OpenReadBack(error) => {
				write!(formatter, "opening stage read-back failed ({error})")
			}
			Self::ReadBack(error) => write!(formatter, "stage read-back failed ({error})"),
			Self::RevalidateReadBack(error) => {
				write!(formatter, "stage read-back revalidation failed ({error})")
			}
			Self::DigestMismatch { .. } => formatter.write_str("stage read-back digest mismatch"),
		}
	}
}

impl Error for StageTransferFailure {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::InitialStage(error)
			| Self::ApplyMetadata(error)
			| Self::CloseStage(error)
			| Self::OpenReadBack(error)
			| Self::RevalidateReadBack(error) => Some(error),
			Self::InvalidInput(error) => Some(error),
			Self::RevalidateSource(error) | Self::AdmitMetadata(error) => Some(error),
			Self::Copy(error) => Some(error),
			Self::ReadBack(error) => Some(error),
			Self::ExtentMismatch { .. }
			| Self::ScratchTooLarge { .. }
			| Self::DigestMismatch { .. } => None,
		}
	}
}

#[test]
fn source_copy_diagnostic_names_the_start_of_the_requested_range() {
	let failure = StageTransferFailure::Copy(CopyMeasureError::Read {
		offset: 4096,
		source: ManagedReadError::SourceChanged,
	});
	assert_eq!(
		failure.to_string(),
		"source range beginning at byte 4096 could not be read: selected child's identity or metadata changed"
	);
}
