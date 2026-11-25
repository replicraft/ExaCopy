//! Read-only admission of a caller-selected, one-file public copy bundle.

use core::fmt;

use exacopy_codec::{
	DocumentError, PlanBody, PlanEntriesPage, PlanEntry, PlanError, PlanExtensions,
	PlanIdentityPlatform, PlanOperation, PlanPath, PlanViewConsistency, UnixTimestamp,
};

use crate::copy_planning::{COPY_POLICY, CREATE_NEW, READ_CONTENT};

#[cfg(test)]
mod tests;

const LINUX_ID_COMPONENT_BYTES: usize = 8;

/// The digest, names, and metadata policy selected independently of the bundle.
#[derive(Clone, Copy)]
pub struct ExpectedCopyPlan<'selection> {
	/// Canonical body digest bound by the caller to its reviewed plan.
	pub digest: [u8; 32],
	/// Exact source root label and raw basename selected by the caller.
	pub source: PlanPath<'selection>,
	/// Exact destination root label and raw basename selected by the caller.
	pub destination: PlanPath<'selection>,
	/// Expected digest of the metadata policy selected by the caller.
	pub metadata_policy_digest: [u8; 32],
	/// Current time obtained independently of the bundle.
	pub now: UnixTimestamp,
}

/// An admitted body and leaf describing one preserve-mode copy request.
///
/// This value carries no filesystem handles or permission. It records historical
/// observations. Consumers must separately bind roots and grants, honor approval,
/// revalidate current names and identities, and establish metadata and durability.
#[derive(Debug)]
pub struct AdmittedCopyPlan<'bundle> {
	body: PlanBody<'bundle>,
	page: PlanEntriesPage<'bundle>,
}

impl<'bundle> AdmittedCopyPlan<'bundle> {
	/// Returns the digest-bound body, including its requested limits and approval field.
	#[must_use]
	pub const fn body(&self) -> &PlanBody<'bundle> {
		&self.body
	}

	/// Returns the admitted create-new leaf's historical observations and expected stream.
	#[must_use]
	pub const fn entry(&self) -> PlanEntry<'bundle> {
		self.page.entry()
	}
}

/// A refused public copy bundle. No files have been opened or changed.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanAdmissionError {
	/// The body failed canonical decoding or digest verification.
	Body(PlanError),
	/// The page failed canonical decoding or verification against its parent reference.
	Page(DocumentError),
	/// A policy, grant label, extension, or root, view or page shape is unsupported.
	UnsupportedProfile,
	/// The body does not declare complete enumeration.
	Incomplete,
	/// The body declares unresolved conflicts.
	Conflict,
	/// A supplied expiration has passed.
	Expired,
	/// Planning or source-view evidence is dated after its applicable boundary.
	FutureObservation,
	/// Root labels or exact raw names differ from the selected ones.
	SelectionMismatch,
	/// The entry does not bind the selected live view.
	ViewMismatch,
	/// The entry and view lack matching Linux device and inode observations.
	SourceIdentityMismatch,
	/// The entry names a different metadata policy from the selected one.
	MetadataPolicyMismatch,
}

impl fmt::Display for PlanAdmissionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Body(error) => write!(formatter, "public copy body refused ({error})"),
			Self::Page(error) => write!(formatter, "public copy entry page refused ({error})"),
			Self::UnsupportedProfile => formatter.write_str("unsupported public copy profile"),
			Self::Incomplete => formatter.write_str("public copy plan is incomplete"),
			Self::Conflict => formatter.write_str("public copy plan declares unresolved conflicts"),
			Self::Expired => formatter.write_str("public copy plan has expired"),
			Self::FutureObservation => formatter.write_str("public copy observations are misdated"),
			Self::SelectionMismatch => {
				formatter.write_str("public copy path differs from selection")
			}
			Self::ViewMismatch => {
				formatter.write_str("public copy entry lacks a matching live view")
			}
			Self::SourceIdentityMismatch => {
				formatter.write_str("public copy observations lack matching source identities")
			}
			Self::MetadataPolicyMismatch => {
				formatter.write_str("public copy metadata policy differs")
			}
		}
	}
}

impl core::error::Error for PlanAdmissionError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Body(error) => Some(error),
			Self::Page(error) => Some(error),
			_ => None,
		}
	}
}

/// Admits canonical body and page bytes for one file and an expected-absent destination.
///
/// The caller supplies both byte slices. This function never retrieves a page
/// or resolves a path. The admitted profile requests live-observed, independent
/// writes, BLAKE3 read-back, per-file publication, required data and process-crash
/// durability and separate approval. It permits neither incumbent replacement
/// nor source retirement. Equal root labels are allowed for distinct raw names.
/// Historical identity comparisons establish neither current filesystem facts
/// nor whether root labels alias on the filesystem.
///
/// # Errors
/// Refuses invalid encoding or digests, unsupported policy or shape, incomplete
/// or conflicting plans, expired or misdated observations, and mismatched bindings.
pub fn admit_single_file_plan<'bundle>(
	body_bytes: &'bundle [u8],
	page_bytes: &'bundle [u8],
	expected: ExpectedCopyPlan<'_>,
) -> Result<AdmittedCopyPlan<'bundle>, PlanAdmissionError> {
	let body = PlanBody::from_canonical_cbor(expected.digest, body_bytes)
		.map_err(PlanAdmissionError::Body)?;
	let fields = body.fields();
	if !fields.complete {
		return Err(PlanAdmissionError::Incomplete);
	}
	if fields.conflict_count != 0 {
		return Err(PlanAdmissionError::Conflict);
	}
	let ([source_root], [reference], [view]) = (
		fields.source_roots.as_slice(),
		fields.entry_pages.as_slice(),
		fields.source_views.as_slice(),
	) else {
		return Err(PlanAdmissionError::UnsupportedProfile);
	};
	if fields.operation != PlanOperation::Copy
		|| fields.policy != COPY_POLICY
		|| !fields.approval_required
		|| fields.entry_count != 1
		|| fields.extensions != PlanExtensions::empty()
		|| !matches!(
			fields.required_grants.as_slice(),
			[READ_CONTENT, CREATE_NEW] | [CREATE_NEW, READ_CONTENT]
		) {
		return Err(PlanAdmissionError::UnsupportedProfile);
	}
	if fields.created_at > expected.now || view.observed_at > fields.created_at {
		return Err(PlanAdmissionError::FutureObservation);
	}
	if fields
		.expires_at
		.is_some_and(|expires| expires <= expected.now)
	{
		return Err(PlanAdmissionError::Expired);
	}
	if *source_root != expected.source.root_id
		|| fields.destination_root != expected.destination.root_id
	{
		return Err(PlanAdmissionError::SelectionMismatch);
	}

	let page = PlanEntriesPage::from_canonical_cbor(*reference, page_bytes)
		.map_err(PlanAdmissionError::Page)?;
	let entry = page.entry();
	if entry.source != expected.source || entry.destination != expected.destination {
		return Err(PlanAdmissionError::SelectionMismatch);
	}
	if view.root_id != entry.source.root_id
		|| view.view_id != entry.source_view_id
		|| view.consistency != PlanViewConsistency::LiveObserved
		|| view.snapshot_token_digest.is_some()
		|| view.stable_until.is_some()
	{
		return Err(PlanAdmissionError::ViewMismatch);
	}
	let Some(identity) = entry.source_identity else {
		return Err(PlanAdmissionError::SourceIdentityMismatch);
	};
	if view.source_identity != Some(identity)
		|| identity.platform != PlanIdentityPlatform::Linux
		|| identity.volume_id.len() != LINUX_ID_COMPONENT_BYTES
		|| identity.object_id.len() != LINUX_ID_COMPONENT_BYTES
		|| identity.generation.is_some()
	{
		return Err(PlanAdmissionError::SourceIdentityMismatch);
	}
	if entry.metadata_policy_digest != expected.metadata_policy_digest {
		return Err(PlanAdmissionError::MetadataPolicyMismatch);
	}
	Ok(AdmittedCopyPlan { body, page })
}
