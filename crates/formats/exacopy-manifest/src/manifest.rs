use core::fmt;

use exacopy_core::UnixComponent;
use uuid::Uuid;

use crate::portable::MAX_LOGICAL_LENGTH;

mod canonical;
mod error;
mod json;

pub use error::{ManifestError, ManifestInvalid, ManifestUnsupported};

/// Maximum encoded JSON bytes admitted by the single-file manifest profile.
pub const MAX_MANIFEST_JSON_BYTES: usize = 16 * 1024;
const MANIFEST_DOMAIN: &[u8] = b"ExaCopy/manifest/v1\0";

/// One regular file's unnamed stream in the unsigned portable manifest profile.
#[derive(Clone, Eq, PartialEq)]
pub struct SingleFileManifest {
	manifest_id: Uuid,
	root_id: Uuid,
	basename: Box<[u8]>,
	length: u64,
	content_digest: [u8; 32],
}

impl SingleFileManifest {
	/// Creates a single-file manifest from a complete observation of its unnamed stream.
	///
	/// Identifiers are opaque and confer no filesystem authority. The stream digest is
	/// ordinary BLAKE3-256 of the observed file bytes.
	///
	/// # Errors
	/// Rejects nil identifiers, invalid Unix basenames, and lengths above the signed limit.
	pub fn new(
		manifest_id: Uuid,
		root_id: Uuid,
		basename: &[u8],
		length: u64,
		content_digest: [u8; 32],
	) -> Result<Self, ManifestError> {
		if manifest_id.is_nil() || root_id.is_nil() {
			return Err(ManifestInvalid::Identifier.into());
		}
		if UnixComponent::new(basename).is_err() {
			return Err(ManifestInvalid::Basename.into());
		}
		if length > MAX_LOGICAL_LENGTH {
			return Err(ManifestInvalid::Length.into());
		}
		Ok(Self {
			manifest_id,
			root_id,
			basename: basename.into(),
			length,
			content_digest,
		})
	}

	/// Returns the manifest identifier.
	#[must_use]
	pub const fn manifest_id(&self) -> Uuid {
		self.manifest_id
	}

	/// Returns the opaque portable root identifier.
	#[must_use]
	pub const fn root_id(&self) -> Uuid {
		self.root_id
	}

	/// Returns the exact Unix basename bytes.
	#[must_use]
	pub fn basename(&self) -> &[u8] {
		&self.basename
	}

	/// Returns the observed logical stream length.
	#[must_use]
	pub const fn length(&self) -> u64 {
		self.length
	}

	/// Returns the ordinary BLAKE3-256 file digest in output byte order.
	#[must_use]
	pub const fn content_digest(&self) -> [u8; 32] {
		self.content_digest
	}

	/// Emits the canonical CBOR projection of the unsigned manifest body.
	#[must_use]
	pub fn canonical_body(&self) -> Vec<u8> {
		canonical::encode(self)
	}

	/// Returns the domain-separated BLAKE3-256 digest of the canonical body.
	#[must_use]
	pub fn digest(&self) -> [u8; 32] {
		let mut hasher = blake3::Hasher::new();
		hasher.update(MANIFEST_DOMAIN);
		hasher.update(&self.canonical_body());
		*hasher.finalize().as_bytes()
	}

	/// Loads the supported manifest from a bounded JSON envelope and verifies its body digest.
	///
	/// # Errors
	/// Reports invalid encoding, an unsupported representation, or an integrity mismatch.
	pub fn from_json(input: &[u8]) -> Result<Self, ManifestError> {
		json::decode(input)
	}

	/// Writes the JSON interoperability envelope with its canonical body digest.
	///
	/// # Errors
	/// Returns an encoding error if JSON serialization fails.
	pub fn to_json(&self) -> Result<Vec<u8>, ManifestError> {
		json::encode(self)
	}
}

impl fmt::Debug for SingleFileManifest {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("SingleFileManifest")
			.field("manifest_id", &self.manifest_id)
			.field("root_id", &self.root_id)
			.field("length", &self.length)
			.finish_non_exhaustive()
	}
}
