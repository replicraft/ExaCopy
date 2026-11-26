//! Bounded single-file manifest and paired baseline leaf encoding and admission.
#![forbid(unsafe_code)]

mod manifest;
mod portable;
pub mod sync_baseline;

pub use manifest::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
