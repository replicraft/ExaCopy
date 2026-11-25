//! The one-entry regular-file slice of the public PlanEntries page format.

use core::fmt;

use uuid::Uuid;

use crate::document::{DocumentError, DocumentPageKind, DocumentRef, document_page_id};
use crate::plan_identity::PlanSourceIdentity;
use crate::portable::{MAX_LOGICAL_LENGTH, valid_unix_basename};

mod wire;

/// A root-relative plan path consisting of one raw Unix component.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PlanPath<'page> {
	/// Opaque root ID to bind separately against a caller-authorized root.
	pub root_id: Uuid,
	/// Exact single component with no display annotation.
	pub basename: &'page [u8],
}

/// Fields of one regular-file, create-new plan entry.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PlanEntry<'page> {
	/// Opaque, non-nil entry ID.
	pub entry_id: Uuid,
	/// Selected source path.
	pub source: PlanPath<'page>,
	/// Intended destination path, with an observation of name absence.
	pub destination: PlanPath<'page>,
	/// Opaque, non-nil source-view ID to bind against the parent plan.
	pub source_view_id: Uuid,
	/// A past source identity observation, if supplied.
	pub source_identity: Option<PlanSourceIdentity<'page>>,
	/// Bounded logical length of the unnamed stream.
	pub stream_length: u64,
	/// Ordinary BLAKE3-256 digest of the unnamed stream.
	pub stream_digest: [u8; 32],
	/// Digest of the required metadata policy.
	pub metadata_policy_digest: [u8; 32],
	/// Estimated independent working bytes.
	pub estimated_working_bytes: u64,
}

/// One immutable v1 leaf of kind `plan_entries`, containing one `create_new` entry.
///
/// Parsing checks the supplied reference and canonical page bytes. Any path,
/// result, or expected absence is planning evidence. Binding an authorized root,
/// resolving a source view, and revalidating observations require a separate caller.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PlanEntriesPage<'page>(PlanEntry<'page>);

impl<'page> PlanEntriesPage<'page> {
	/// Creates the supported one-entry leaf from validated observation values.
	///
	/// # Errors
	/// Rejects nil IDs, unsafe paths, overlapping paths, excessive stream length,
	/// or out-of-bounds identity observations.
	pub fn new(entry: PlanEntry<'page>) -> Result<Self, DocumentError> {
		if entry.entry_id.is_nil() || entry.source_view_id.is_nil() {
			return Err(DocumentError::InvalidEntry);
		}
		for path in [entry.source, entry.destination] {
			if path.root_id.is_nil() || !valid_unix_basename(path.basename) {
				return Err(DocumentError::InvalidEntry);
			}
		}
		if entry.source == entry.destination || entry.stream_length > MAX_LOGICAL_LENGTH {
			return Err(DocumentError::InvalidEntry);
		}
		if entry
			.source_identity
			.is_some_and(|identity| !identity.is_bounded())
		{
			return Err(DocumentError::InvalidEntry);
		}
		Ok(Self(entry))
	}

	/// Parses one bounded canonical leaf against the page reference from its parent.
	///
	/// # Errors
	/// Rejects bounds, kind, digest, count, encoding, and profile mismatches.
	pub fn from_canonical_cbor(
		reference: DocumentRef,
		input: &'page [u8],
	) -> Result<Self, DocumentError> {
		reference.verify(DocumentPageKind::PlanEntries, input)?;
		if reference.item_count() != 1 {
			return Err(DocumentError::CountMismatch);
		}
		let page = Self::new(wire::decode(input)?)?;
		if page.canonical_cbor() != input {
			return Err(DocumentError::NonCanonical);
		}
		Ok(page)
	}

	/// Returns the validated planning fields, borrowing opaque observations.
	#[must_use]
	pub const fn entry(self) -> PlanEntry<'page> {
		self.0
	}

	/// Encodes the registered leaf body with deterministic CBOR.
	#[must_use]
	pub fn canonical_cbor(self) -> Vec<u8> {
		wire::encode(self.0)
	}

	/// Returns the derived reference for this exact canonical leaf.
	#[must_use]
	pub fn document_ref(self) -> DocumentRef {
		let bytes = self.canonical_cbor();
		let kind = DocumentPageKind::PlanEntries;
		DocumentRef::new(document_page_id(kind, &bytes), kind, bytes.len() as u64, 1)
			.expect("one validated bounded entry fits the document page limit")
	}
}

impl fmt::Debug for PlanEntriesPage<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PlanEntriesPage")
			.field("entry_id", &self.0.entry_id)
			.field("source_view_id", &self.0.source_view_id)
			.finish_non_exhaustive()
	}
}
