//! The registered canonical public Plan v1 body and its digest.

use std::borrow::Cow;
use std::fmt;

use uuid::{Uuid, Variant};

use crate::document::{DocumentPageKind, DocumentRef};

mod error;
mod evidence;
mod extensions;
mod policy;
mod wire;

pub use error::PlanError;
pub use evidence::{PlanResourceLimits, PlanSourceView, UnixTimestamp};
pub use extensions::PlanExtensions;
pub use policy::{
	PlanConflict, PlanConsistency, PlanDurability, PlanFidelity, PlanOperation, PlanPolicy,
	PlanPreservation, PlanPublication, PlanSourceRetirement, PlanStorage, PlanVerification,
	PlanViewConsistency,
};

/// Maximum canonical Plan body admitted by the local PLN-002 profile.
pub const MAX_PLAN_BODY_BYTES: usize = 1024 * 1024;

const PLAN_DOMAIN: &[u8] = b"ExaCopy/plan/v1\0";
const MAX_ROOTS: usize = 128;
const MAX_PAGES: usize = 4_096;
const MAX_SOURCE_VIEWS: usize = 128;
const MAX_GRANTS: usize = 128;
const MAX_LABEL_SCALARS: usize = 128;

/// Fields of the canonical public Plan v1 body.
#[derive(Clone, Eq, PartialEq)]
pub struct PlanBodyFields<'body> {
	/// RFC-variant UUIDv7 plan ID.
	pub plan_id: Uuid,
	/// Selected operation.
	pub operation: PlanOperation,
	/// Creation time as a signed Unix time.
	pub created_at: UnixTimestamp,
	/// Advisory expiry, when supplied.
	pub expires_at: Option<UnixTimestamp>,
	/// Ordered source root identifiers to bind separately.
	pub source_roots: Vec<Uuid>,
	/// Destination root identifier to bind separately.
	pub destination_root: Uuid,
	/// Ordered references to the selected entry pages.
	pub entry_pages: Vec<DocumentRef>,
	/// Required safety and fidelity policy.
	pub policy: PlanPolicy,
	/// Requested I/O and memory budget limits.
	pub resource_limits: PlanResourceLimits,
	/// Whether separately bound approval is required.
	pub approval_required: bool,
	/// Ordered source-view descriptors.
	pub source_views: Vec<PlanSourceView<'body>>,
	/// Ordered names of externally checked grants.
	pub required_grants: Vec<&'body str>,
	/// Estimated independent working bytes.
	pub estimated_working_bytes: u64,
	/// Declared conflict count.
	pub conflict_count: u64,
	/// Total item count advertised by the root page references.
	pub entry_count: u64,
	/// The caller's declared enumeration completeness.
	pub complete: bool,
	/// Validated opaque optional extensions.
	pub extensions: PlanExtensions<'body>,
}

/// An immutable, bounded Plan v1 body and its canonical representation.
///
/// The body carries requests and past observations. Its bytes, digest and
/// recorded completeness convey no approval, capability or present-day fact.
#[derive(Clone, Eq, PartialEq)]
pub struct PlanBody<'body> {
	fields: PlanBodyFields<'body>,
	encoded: Cow<'body, [u8]>,
}

impl<'body> PlanBody<'body> {
	/// Validates fields and writes their exact registered canonical projection.
	///
	/// # Errors
	/// Rejects unsupported values, bounds violations, invalid identities, and
	/// inconsistent declared page totals.
	pub fn new(fields: PlanBodyFields<'body>) -> Result<Self, PlanError> {
		validate_fields(&fields)?;
		let encoded = wire::encode(&fields);
		check_size(&encoded)?;
		Ok(Self {
			fields,
			encoded: Cow::Owned(encoded),
		})
	}

	/// Admits a canonical body against an expected digest supplied by the caller.
	///
	/// The caller separately binds the expectation to its parent or reviewed
	/// record. The codec does not validate filesystem facts or page contents.
	///
	/// # Errors
	/// Rejects oversized, mismatched, malformed, unsupported, or noncanonical input.
	pub fn from_canonical_cbor(
		expected_digest: [u8; 32],
		input: &'body [u8],
	) -> Result<Self, PlanError> {
		check_size(input)?;
		if digest_bytes(input) != expected_digest {
			return Err(PlanError::Integrity);
		}
		let fields = wire::decode(input)?;
		validate_fields(&fields)?;
		if wire::encode(&fields) != input {
			return Err(PlanError::NonCanonical);
		}
		Ok(Self {
			fields,
			encoded: Cow::Borrowed(input),
		})
	}

	/// Reads the validated fields without changing the digest-bound body.
	#[must_use]
	pub const fn fields(&self) -> &PlanBodyFields<'body> {
		&self.fields
	}

	/// Returns the deterministic CBOR body bytes.
	#[must_use]
	pub fn canonical_cbor(&self) -> &[u8] {
		&self.encoded
	}

	/// Computes the ordinary BLAKE3-256 digest in the public Plan v1 domain.
	#[must_use]
	pub fn digest(&self) -> [u8; 32] {
		digest_bytes(self.canonical_cbor())
	}
}

impl fmt::Debug for PlanBody<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PlanBody")
			.field("plan_id", &self.fields.plan_id)
			.field("operation", &self.fields.operation)
			.field("entry_count", &self.fields.entry_count)
			.finish_non_exhaustive()
	}
}

fn validate_fields(fields: &PlanBodyFields<'_>) -> Result<(), PlanError> {
	if fields.source_roots.len() > MAX_ROOTS
		|| fields.entry_pages.len() > MAX_PAGES
		|| fields.source_views.len() > MAX_SOURCE_VIEWS
		|| fields.required_grants.len() > MAX_GRANTS
	{
		return Err(PlanError::Bounds);
	}
	if fields.plan_id.get_version_num() != 7
		|| fields.plan_id.get_variant() != Variant::RFC4122
		|| fields.destination_root.is_nil()
		|| fields.source_roots.iter().any(Uuid::is_nil)
	{
		return Err(PlanError::Identifier);
	}
	for grant in &fields.required_grants {
		check_label(grant)?;
	}
	for view in &fields.source_views {
		if view.view_id.is_nil() || view.root_id.is_nil() || view.measurement_id.is_nil() {
			return Err(PlanError::Identifier);
		}
		check_label(view.provider)?;
		if view
			.source_identity
			.is_some_and(|identity| !identity.is_bounded())
		{
			return Err(PlanError::Bounds);
		}
	}

	let mut count = 0_u64;
	for page in &fields.entry_pages {
		if page.kind() != DocumentPageKind::PlanEntries {
			return Err(PlanError::PageReference);
		}
		count = count
			.checked_add(page.item_count())
			.ok_or(PlanError::Bounds)?;
	}
	if count != fields.entry_count {
		return Err(PlanError::CountMismatch);
	}
	Ok(())
}

fn check_label(text: &str) -> Result<(), PlanError> {
	// At most four bytes per valid Unicode scalar.
	if text.len() > MAX_LABEL_SCALARS * 4 || text.chars().count() > MAX_LABEL_SCALARS {
		return Err(PlanError::Bounds);
	}
	Ok(())
}

fn check_size(bytes: &[u8]) -> Result<(), PlanError> {
	if bytes.len() > MAX_PLAN_BODY_BYTES {
		return Err(PlanError::Size);
	}
	Ok(())
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
	*blake3::Hasher::new()
		.update(PLAN_DOMAIN)
		.update(bytes)
		.finalize()
		.as_bytes()
}
