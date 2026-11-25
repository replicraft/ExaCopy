//! Pure bounded codecs for portable ExaCopy records.
#![forbid(unsafe_code)]

mod cbor;
mod document;
mod manifest;
mod plan;
mod plan_entries;
mod plan_identity;
mod portable;

pub use document::{DocumentError, DocumentPageKind, DocumentRef, MAX_DOCUMENT_PAGE_BYTES};
pub use manifest::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
pub use plan::{
	MAX_PLAN_BODY_BYTES, MAX_PLAN_JSON_BYTES, PlanBody, PlanBodyFields, PlanConflict,
	PlanConsistency, PlanDurability, PlanError, PlanExtensions, PlanFidelity, PlanJsonError,
	PlanOperation, PlanPolicy, PlanPreservation, PlanPublication, PlanResourceLimits,
	PlanSourceRetirement, PlanSourceView, PlanStorage, PlanVerification, PlanViewConsistency,
	PublicPlan, UnixTimestamp,
};
pub use plan_entries::{PlanEntriesPage, PlanEntry, PlanPath};
pub use plan_identity::{MAX_PLAN_IDENTITY_BYTES, PlanIdentityPlatform, PlanSourceIdentity};
