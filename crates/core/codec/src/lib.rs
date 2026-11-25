//! Pure bounded codecs for portable ExaCopy records.
#![forbid(unsafe_code)]

mod cbor;
mod manifest;
mod portable;

pub use manifest::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
