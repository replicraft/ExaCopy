//! Pure bounded codecs for portable ExaCopy records.
#![forbid(unsafe_code)]

mod manifest;

pub use manifest::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
