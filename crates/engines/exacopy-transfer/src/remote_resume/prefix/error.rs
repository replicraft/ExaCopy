use std::fmt;

use exacopy_content::StreamInputError;
use exacopy_journal::remote_download::RemoteDownloadError;

/// Failure to obtain matching current bytes over the proposed prefix.
#[derive(Debug)]
#[non_exhaustive]
pub enum PrefixVerificationError<R, L> {
	/// The selected history cannot justify this prefix.
	History(RemoteDownloadError),
	/// Source length or scratch exceed the chosen bounds.
	Input(StreamInputError),
	/// The retained stage does not match the exact accepted prepared identity.
	StageIdentity,
	/// The fresh source passed a stale or unexpected epoch.
	Epoch,
	/// The fresh source exceeds the signed extent limit.
	SourceLimit {
		/// Observed source length.
		length: u64,
		/// Signed maximum source length.
		limit: u64,
	},
	/// The held stage does not cover the checkpoints or has an excess tail.
	RetainedExtent {
		/// Observed retained length.
		extent: u64,
		/// Exact end of accepted checkpoint ranges.
		checkpoint: u64,
	},
	/// The file exceeds the extent the prior active capture was allowed to write.
	RetainedBeyondPrior {
		/// Observed retained length.
		extent: u64,
		/// Extent authorized by the prior active capture.
		prior: u64,
	},
	/// The newly opened source is shorter than the proposed retained coverage.
	SourceShorter {
		/// Observed source length.
		source: u64,
		/// Proposed retained length.
		retained: u64,
	},
	/// The observed length changed on the same fresh source during verification.
	SourceExtent {
		/// Original source length.
		expected: u64,
		/// Later source length.
		actual: u64,
	},
	/// The retained file length changed during verification.
	StageExtentChanged {
		/// Original retained file length.
		expected: u64,
		/// Later retained file length.
		actual: u64,
	},
	/// Fresh held source reobservation failed.
	SourceObservation(R),
	/// Exact fresh source positioned read failed.
	SourceRead {
		/// Window start.
		offset: u64,
		/// Source error.
		cause: R,
	},
	/// Held retained stage reobservation failed.
	StageObservation(L),
	/// Exact positioned read of the held stage failed.
	StageRead {
		/// Window start.
		offset: u64,
		/// Stage read error.
		cause: L,
	},
	/// Historical digest differs from the actual held stage.
	CheckpointMismatch {
		/// Checkpoint range start.
		offset: u64,
	},
	/// The correctly checkpointed local range differs from the fresh source.
	SourceMismatch {
		/// Checkpoint range start.
		offset: u64,
	},
	/// Fresh source and retained stage disagree in the uncheckpointed tail.
	TailMismatch {
		/// Uncheckpointed tail start.
		offset: u64,
	},
	/// The checked suffix reader cannot continue after a failed or interrupted operation.
	ContinuationStopped,
	/// The live source has not been read through its complete observed extent.
	IncompleteContinuation {
		/// First byte still needed.
		offset: u64,
		/// Complete observed source length.
		length: u64,
	},
	/// Terminal source observation, EOF or handle closure failed.
	SourceFinish(R),
}

impl<R: fmt::Display, L: fmt::Display> fmt::Display for PrefixVerificationError<R, L> {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ContinuationStopped => out.write_str("retained source continuation has stopped"),
			Self::IncompleteContinuation { offset, length } => {
				write!(
					out,
					"retained source read stopped at {offset} of {length} bytes"
				)
			}
			Self::SourceFinish(cause) => write!(out, "terminal source check failed ({cause})"),
			Self::History(cause) => cause.fmt(out),
			Self::Input(cause) => cause.fmt(out),
			Self::StageIdentity => out.write_str("held stage differs from the prepared stage"),
			Self::Epoch => out.write_str("source did not supply the exact fresh epoch"),
			Self::SourceLimit { length, limit } => {
				write!(
					out,
					"fresh source extent {length} exceeds signed limit {limit}"
				)
			}
			Self::RetainedExtent { extent, checkpoint } => {
				write!(
					out,
					"retained extent {extent} cannot extend checkpoint prefix {checkpoint}"
				)
			}
			Self::RetainedBeyondPrior { extent, prior } => {
				write!(
					out,
					"retained extent {extent} exceeds the prior capture extent {prior}"
				)
			}
			Self::SourceShorter { source, retained } => {
				write!(
					out,
					"fresh source extent {source} is shorter than retained extent {retained}"
				)
			}
			Self::SourceExtent { expected, actual } => {
				write!(
					out,
					"held source extent changed from {expected} to {actual}"
				)
			}
			Self::StageExtentChanged { expected, actual } => {
				write!(out, "held stage extent changed from {expected} to {actual}")
			}
			Self::SourceObservation(cause) => {
				write!(out, "fresh source observation failed ({cause})")
			}
			Self::SourceRead { offset, cause } => {
				write!(out, "fresh source read at {offset} failed ({cause})")
			}
			Self::StageObservation(cause) => {
				write!(out, "retained stage observation failed ({cause})")
			}
			Self::StageRead { offset, cause } => {
				write!(out, "retained stage read at {offset} failed ({cause})")
			}
			Self::CheckpointMismatch { offset } => write!(
				out,
				"retained range at {offset} differs from its checkpoint"
			),
			Self::SourceMismatch { offset } => write!(
				out,
				"fresh source differs from checkpointed bytes at {offset}"
			),
			Self::TailMismatch { offset } => {
				write!(out, "fresh source and retained tail differ from {offset}")
			}
		}
	}
}

impl<R: std::error::Error + 'static, L: std::error::Error + 'static> std::error::Error
	for PrefixVerificationError<R, L>
{
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::History(cause) => Some(cause),
			Self::Input(cause) => Some(cause),
			Self::SourceObservation(cause)
			| Self::SourceRead { cause, .. }
			| Self::SourceFinish(cause) => Some(cause),
			Self::StageObservation(cause) | Self::StageRead { cause, .. } => Some(cause),
			_ => None,
		}
	}
}
