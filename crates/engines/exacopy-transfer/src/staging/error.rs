use std::error::Error;
use std::fmt;

use exacopy_content::{ContentDigest, CopyMeasureError, MeasureError, StreamInputError};
/// Admission, source, stage or verification failure during a private transfer.
#[derive(Debug)]
pub enum StageCopyFailure<R, W> {
	/// The stage writer could not be admitted as fresh.
	InitialStage(W),
	/// The captured source length differs from the stage's declared extent.
	ExtentMismatch {
		/// Captured source length in bytes.
		source_length: u64,
		/// Declared stage length in bytes.
		stage_length: u64,
	},
	/// Scratch is larger than the stage I/O limit.
	ScratchTooLarge {
		/// Supplied buffer length in bytes.
		length: usize,
	},
	/// Stream length or scratch failed baseline stream validation.
	InvalidInput(StreamInputError),
	/// The source could not be revalidated before or after the transfer.
	RevalidateSource(R),
	/// The source did not satisfy the strict metadata profile before transfer.
	AdmitMetadata(R),
	/// The verified stage could not install and synchronize the required metadata.
	ApplyMetadata(W),
	/// A source read or private write could not complete.
	Copy(CopyMeasureError<R, W>),
	/// The stage could not complete the barrier and confirmed writer closure.
	CloseStage(W),
	/// The independent read-only descriptor could not be opened.
	OpenReadBack(W),
	/// The independent reader did not observe the declared extent.
	ReadBackExtentMismatch {
		/// Declared stage length in bytes.
		stage_length: u64,
		/// Captured read-back length in bytes.
		read_back_length: u64,
	},
	/// The independent read-back did not complete.
	ReadBack(MeasureError<W>),
	/// The reader could not confirm the same private stage at its logical EOF.
	RevalidateReadBack(W),
	/// The complete source stream and independent read-back measured different digests.
	DigestMismatch {
		/// Digest computed from bytes supplied by the source reader.
		source_digest: ContentDigest,
		/// Digest computed independently from the private stage.
		stage_digest: ContentDigest,
	},
}

impl<R: fmt::Display, W: fmt::Display> fmt::Display for StageCopyFailure<R, W> {
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
			Self::ScratchTooLarge { length } => {
				write!(formatter, "scratch length {length} exceeds the stage limit")
			}
			Self::InvalidInput(error) => error.fmt(formatter),
			Self::RevalidateSource(error) => {
				write!(formatter, "source revalidation failed ({error})")
			}
			Self::AdmitMetadata(error) => write!(formatter, "source metadata refused ({error})"),
			Self::ApplyMetadata(error) => write!(formatter, "stage metadata failed ({error})"),
			Self::Copy(error) => error.fmt(formatter),
			Self::CloseStage(error) => {
				write!(formatter, "stage barrier or closure failed ({error})")
			}
			Self::OpenReadBack(error) => {
				write!(formatter, "opening stage read-back failed ({error})")
			}
			Self::ReadBackExtentMismatch {
				stage_length,
				read_back_length,
			} => write!(
				formatter,
				"read-back extent {read_back_length} differs from stage extent {stage_length}"
			),
			Self::ReadBack(error) => write!(formatter, "stage read-back failed ({error})"),
			Self::RevalidateReadBack(error) => {
				write!(formatter, "stage read-back revalidation failed ({error})")
			}
			Self::DigestMismatch { .. } => formatter.write_str("stage read-back digest mismatch"),
		}
	}
}

impl<R: Error + 'static, W: Error + 'static> Error for StageCopyFailure<R, W> {
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
			| Self::ReadBackExtentMismatch { .. }
			| Self::ScratchTooLarge { .. }
			| Self::DigestMismatch { .. } => None,
		}
	}
}
