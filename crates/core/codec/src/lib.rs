//! Pure bounded codecs for portable ExaCopy records.
#![forbid(unsafe_code)]

mod cbor;
mod document;
mod manifest;
mod plan_entries;
mod portable;

pub use document::{DocumentError, DocumentPageKind, DocumentRef, MAX_DOCUMENT_PAGE_BYTES};
pub use manifest::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
pub use plan_entries::{
	MAX_PLAN_IDENTITY_BYTES, PlanEntriesPage, PlanEntry, PlanIdentityPlatform, PlanPath,
	PlanSourceIdentity,
};
