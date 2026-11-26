//! Bounded public Plan encoding, document pages, and admission.
#![forbid(unsafe_code)]

mod bundle;
mod cbor;
mod document;
mod plan;
mod plan_entries;
mod plan_identity;
mod portable;

pub use bundle::{PlanBundleArtifacts, PlanBundleEncodingError, RenderedPlanEnvelope};
pub use document::{DocumentError, DocumentPageKind, DocumentRef, MAX_DOCUMENT_PAGE_BYTES};
pub use plan::{
	MAX_PLAN_BODY_BYTES, MAX_PLAN_JSON_BYTES, PlanBody, PlanBodyFields, PlanConflict,
	PlanConsistency, PlanCreationTime, PlanDurability, PlanError, PlanExtensions, PlanFidelity,
	PlanJsonError, PlanOperation, PlanPolicy, PlanPreservation, PlanPublication,
	PlanResourceLimits, PlanSourceRetirement, PlanSourceView, PlanStorage, PlanVerification,
	PlanViewConsistency, PublicPlan, UnixTimestamp, is_plan_id, plan_reference,
};
pub use plan_entries::{PlanEntriesPage, PlanEntry, PlanPath};
pub use plan_identity::{MAX_PLAN_IDENTITY_BYTES, PlanIdentityPlatform, PlanSourceIdentity};

/// Canonical workflow records for synchronization genesis.
pub mod workflow_sync;
