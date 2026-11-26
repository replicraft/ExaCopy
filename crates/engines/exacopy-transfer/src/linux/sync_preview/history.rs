use std::fmt;
use std::num::NonZeroU64;

use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_model::{RegularFileEvidence, SyncBaseline};
use exacopy_plan::workflow_sync::EndpointFacts;

use super::{FirstSyncPreview, MAX_PREVIEW_FILE_BYTES, PreviewInput, SyncPreviewFailure, preview};
use crate::sync_genesis::AuthenticatedSyncGenesis;

/// Exact current subject and ordered endpoint selection obtained from live admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveSyncSelection<'name> {
	/// Current independently selected owner profile ID.
	pub profile: [u8; 16],
	/// Current independently selected owner profile revision.
	pub revision: NonZeroU64,
	/// Current owner key selected independently of the artifact.
	pub owner_key: [u8; 32],
	/// One exact raw basename selected under both roots.
	pub subject: UnixComponent<'name>,
	/// Ordered local endpoint and current native-location facts.
	pub endpoints: [EndpointFacts<'name>; 2],
}

/// Read-only capability for one current pair in the authenticated history profile.
///
/// Implementations must obtain the owner-selected endpoint locators and limits
/// independently of the historical artifacts. They must derive the native facts
/// from the same held roots and exact subject used by the entries. A successful
/// recheck reconfirms the selected profile, both roots and both original subject
/// observations. A denied, stale, unknown or partially observed side must fail
/// the recheck before the engine classifies the path.
pub trait HeldSyncPreview {
	/// Read-only view of a held named file in this pair.
	type View: ReadView;
	/// Failure to establish the complete live selection.
	type Error;

	/// Borrows the initial ordered pair of observations without selecting new resources.
	fn observations(&self) -> [PreviewInput<'_, Self::View>; 2];

	/// Revalidates the held native pair and exact selected subject.
	///
	/// # Errors
	/// Reports unavailable, incomplete or changed scope and subject evidence.
	fn recheck_selection(&self) -> Result<LiveSyncSelection<'_>, Self::Error>;
}

/// Failure to bind authenticated history to the independently admitted live pair.
#[derive(Debug)]
pub enum HistoricalPreviewFailure<R, P> {
	/// Exact selected subject or ordered endpoint scope differs from the historical closure.
	ScopeMismatch,
	/// A side is outside the supported current comparison profile.
	UnsupportedObservation,
	/// Live admission, measurement or final evidence failed.
	Live(SyncPreviewFailure<R, P>),
}

impl<R: fmt::Display, P: fmt::Display> fmt::Display for HistoricalPreviewFailure<R, P> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ScopeMismatch => {
				formatter.write_str("current sync scope differs from selected history")
			}
			Self::UnsupportedObservation => {
				formatter.write_str("current sync scope includes an unsupported entry")
			}
			Self::Live(error) => error.fmt(formatter),
		}
	}
}

impl<R: std::error::Error + 'static, P: std::error::Error + 'static> std::error::Error
	for HistoricalPreviewFailure<R, P>
{
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Live(error) => Some(error),
			_ => None,
		}
	}
}

/// Classifies complete live observations against explicitly authenticated history.
///
/// The selected history must be admitted by the genesis closure verifier. Its
/// matched measurements describe only the common prior state. The read capability
/// must belong to an independently admitted current pair. No history fallback,
/// seed creation, version advancement or effect permit is returned.
///
/// # Errors
/// Rejects mismatching scope, unsupported or incomplete evidence, unreadable
/// or changed live inputs and exceeded read limits.
/// Complete exact absence under an admitted root remains an observation.
pub fn preview_with_history<P: HeldSyncPreview>(
	history: &AuthenticatedSyncGenesis<'_, '_>,
	pair: &P,
	scratch: &mut [u8],
) -> Result<FirstSyncPreview, HistoricalPreviewFailure<<P::View as ReadView>::Error, P::Error>> {
	use HistoricalPreviewFailure as Error;

	let current = pair
		.recheck_selection()
		.map_err(SyncPreviewFailure::Pair)
		.map_err(Error::Live)?;
	if !matches_history(history, current) {
		return Err(Error::ScopeMismatch);
	}
	let inputs = pair.observations();
	if inputs
		.iter()
		.any(|input| matches!(input, PreviewInput::Unsupported))
	{
		return Err(Error::UnsupportedObservation);
	}
	let previous = history.sides()[0];
	let baseline = SyncBaseline::CommonPresent(RegularFileEvidence {
		byte_len: previous.length,
		content_digest: previous.stream_digest,
		required_metadata_digest: previous.metadata_digest,
	});
	let limits = current
		.endpoints
		.map(|endpoint| endpoint.max_bytes.min(MAX_PREVIEW_FILE_BYTES));
	let result = preview(inputs, baseline, limits, scratch, || {
		let confirmed = pair.recheck_selection().map_err(ScopeError::Live)?;
		if !matches_history(history, confirmed) {
			return Err(ScopeError::Mismatch);
		}
		Ok(())
	});
	match result {
		Ok(preview) => Ok(preview),
		Err(SyncPreviewFailure::Pair(ScopeError::Mismatch)) => Err(Error::ScopeMismatch),
		Err(SyncPreviewFailure::Pair(ScopeError::Live(error))) => {
			Err(Error::Live(SyncPreviewFailure::Pair(error)))
		}
		Err(SyncPreviewFailure::ScratchLimit) => Err(Error::Live(SyncPreviewFailure::ScratchLimit)),
		Err(SyncPreviewFailure::FileLimit(side)) => {
			Err(Error::Live(SyncPreviewFailure::FileLimit(side)))
		}
		Err(SyncPreviewFailure::Metadata(side, error)) => {
			Err(Error::Live(SyncPreviewFailure::Metadata(side, error)))
		}
		Err(SyncPreviewFailure::Measure(side, error)) => {
			Err(Error::Live(SyncPreviewFailure::Measure(side, error)))
		}
	}
}

enum ScopeError<E> {
	Live(E),
	Mismatch,
}

fn matches_history(
	history: &AuthenticatedSyncGenesis<'_, '_>,
	current: LiveSyncSelection<'_>,
) -> bool {
	history.root().profile == current.profile
		&& history.profile_revision() == current.revision
		&& history.owner_key() == current.owner_key
		&& history.root().name == current.subject
		&& history.endpoints() == &current.endpoints
}
