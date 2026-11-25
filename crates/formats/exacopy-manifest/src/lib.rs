//! Bounded public single-file manifest encoding and admission.
#![forbid(unsafe_code)]

mod manifest;
mod portable;

pub use manifest::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
