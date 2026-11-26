//! Bounded twin measurement and read-only first-run sync classification.

use std::error::Error;
use std::fmt;

use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_endpoint::ReadView;
use exacopy_manifest::sync_baseline::{LeafError, LinuxOwnerMode};
use exacopy_model::{
	RegularFileEvidence, SyncBaseline, SyncInventoryCompleteness, SyncObservation,
	SyncPathDecision, SyncSide, classify_two_way_path,
};

use crate::manifest;

#[cfg(test)]
mod tests;

/// Maximum bytes read from each side of the selected one-file preview.
pub const MAX_PREVIEW_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// One observation of the exact authorized subject.
#[derive(Debug)]
pub enum PreviewInput<'view, R> {
	/// Held regular-file view and its selected Linux owner-and-mode evidence.
	Present {
		/// The adapter confirms the original name, metadata and EOF via the view.
		view: &'view R,
		/// Mode, UID and GID observed on the same held file.
		metadata: LinuxOwnerMode,
	},
	/// Exact lookup under the held root reported absence.
	Absent,
	/// An entry is known to exist outside the selected profile.
	Unsupported,
}

/// Completed live evidence for one selected basename and no common history.
#[derive(Debug)]
pub struct FirstSyncPreview {
	/// Ordered observations in left-to-right order.
	pub observations: [SyncObservation; 2],
	/// Existing model's decision for the reported pair.
	pub decision: SyncPathDecision,
}

/// Reason a complete live preview could not be produced.
#[derive(Debug)]
pub enum SyncPreviewFailure<R, P> {
	/// The caller did not supply bounded, nonempty scratch space.
	ScratchLimit,
	/// The selected file exceeds the preview read budget.
	FileLimit(SyncSide),
	/// Required metadata cannot be projected under this preview policy.
	Metadata(SyncSide, LeafError),
	/// Independent measurement or its bracketing observation checks failed.
	Measure(SyncSide, manifest::Error<R>),
	/// Final revalidation of the entire current pair failed.
	Pair(P),
}

impl<R: fmt::Display, P: fmt::Display> fmt::Display for SyncPreviewFailure<R, P> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ScratchLimit => formatter.write_str("sync preview scratch exceeds its bounds"),
			Self::FileLimit(side) => write!(
				formatter,
				"{side:?} sync stream exceeds the preview byte limit"
			),
			Self::Metadata(side, error) => write!(
				formatter,
				"could not verify {side:?} sync metadata ({error})"
			),
			Self::Measure(side, error) => write!(
				formatter,
				"could not measure {side:?} sync stream ({error})"
			),
			Self::Pair(error) => write!(formatter, "could not revalidate the sync pair ({error})"),
		}
	}
}

impl<R: Error + 'static, P: Error + 'static> Error for SyncPreviewFailure<R, P> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Metadata(_, error) => Some(error),
			Self::Measure(_, error) => Some(error),
			Self::Pair(error) => Some(error),
			Self::ScratchLimit | Self::FileLimit(_) => None,
		}
	}
}

/// Measures both held observations, revalidates the pair, then classifies with no history.
///
/// The caller binds the same exact subject under two distinct authorized roots,
/// and the supplied pair recheck must reconfirm the original root and entry
/// observations. Historical tuples cannot be substituted for the live views.
///
/// # Errors
/// Refuses unavailable observations, unstable names, and invalid metadata or bounds.
pub fn preview_without_history<R: ReadView, P>(
	inputs: [PreviewInput<'_, R>; 2],
	scratch: &mut [u8],
	recheck_pair: impl FnOnce() -> Result<(), P>,
) -> Result<FirstSyncPreview, SyncPreviewFailure<R::Error, P>> {
	use SyncPreviewFailure as Error;
	use SyncSide::{Left, Right};

	if scratch.is_empty() || scratch.len() > MAX_SCRATCH_BYTES {
		return Err(Error::ScratchLimit);
	}
	for (input, side) in inputs.iter().zip([Left, Right]) {
		if let PreviewInput::Present { view, .. } = input
			&& view.length() > MAX_PREVIEW_FILE_BYTES
		{
			return Err(Error::FileLimit(side));
		}
	}
	let [left, right] = inputs;
	let observations = [
		measure(left, Left, scratch)?,
		measure(right, Right, scratch)?,
	];
	recheck_pair().map_err(Error::Pair)?;
	let [left, right] = observations;
	let decision = classify_two_way_path(
		SyncInventoryCompleteness::Complete,
		SyncBaseline::Uninitialized,
		left,
		right,
	);
	Ok(FirstSyncPreview {
		observations,
		decision,
	})
}

fn measure<R: ReadView, P>(
	input: PreviewInput<'_, R>,
	side: SyncSide,
	scratch: &mut [u8],
) -> Result<SyncObservation, SyncPreviewFailure<R::Error, P>> {
	use SyncPreviewFailure as Error;

	match input {
		PreviewInput::Present { view, metadata } => {
			let required_metadata_digest = metadata
				.digest()
				.map_err(|error| Error::Metadata(side, error))?;
			let stream =
				manifest::measure(view, scratch).map_err(|error| Error::Measure(side, error))?;
			Ok(SyncObservation::Present(RegularFileEvidence {
				byte_len: stream.length,
				content_digest: stream.digest,
				required_metadata_digest,
			}))
		}
		PreviewInput::Absent => Ok(SyncObservation::AbsentObserved),
		PreviewInput::Unsupported => Ok(SyncObservation::UnsupportedEntry),
	}
}
