//! The unsigned JSON presentation of the canonical public Plan v1 body.

mod datetime;
mod error;
mod extensions;
mod limits;
mod schema;

use serde::Deserialize;
use serde_json::value::RawValue;

use super::{PlanBody, PlanError};

pub use error::PlanJsonError;

/// Maximum size of an input or output JSON envelope in the unsigned Plan profile.
///
/// The canonical body has a separate one-MiB limit. JSON expansion includes
/// UTF-8 escaping, base64, decimal text, field names, and UUID spellings.
pub const MAX_PLAN_JSON_BYTES: usize = 8 * super::MAX_PLAN_BODY_BYTES;

const VERSION: &str = "1.0";

/// A digest-checked public Plan in the unsigned JSON profile.
///
/// Owns the canonical body so decoded identity bytes and extension values can
/// be borrowed by a checked body view. No approval or executable grant is
/// represented by this type.
#[derive(Clone, Eq, PartialEq)]
pub struct PublicPlan {
	canonical: Vec<u8>,
	digest: [u8; 32],
}

impl PublicPlan {
	/// Admits a validated body into the unsigned JSON profile.
	///
	/// # Errors
	/// Rejects body timestamps outside the four-digit UTC year range.
	pub fn from_body(body: &PlanBody<'_>) -> Result<Self, PlanJsonError> {
		let fields = body.fields();
		datetime::check(fields.created_at)?;
		if let Some(timestamp) = fields.expires_at {
			datetime::check(timestamp)?;
		}
		for view in &fields.source_views {
			datetime::check(view.observed_at)?;
			if let Some(timestamp) = view.stable_until {
				datetime::check(timestamp)?;
			}
		}
		Ok(Self {
			canonical: body.canonical_cbor().to_vec(),
			digest: body.digest(),
		})
	}

	/// Validates the unsigned envelope and checks its declared canonical-body digest.
	///
	/// # Errors
	/// Rejects oversized, invalid, unsupported, or integrity-mismatched JSON.
	/// An attached approval is outside this profile.
	pub fn from_json(input: &[u8]) -> Result<Self, PlanJsonError> {
		limits::check(input)?;
		let limits::Object(envelope): limits::Object<Envelope<'_>> =
			serde_json::from_slice(input).map_err(|_| PlanJsonError::Json)?;
		if envelope.approval.is_some() {
			return Err(PlanJsonError::Approval);
		}
		let expected = schema::digest(&envelope.digest)?;
		let body = envelope.body.0;
		if body.schema_version != VERSION {
			return Err(PlanJsonError::Version);
		}
		let decoded_views = schema::decode_views(&body.source_views.0)?;
		let extensions = extensions::from_json(body.extensions)?;
		let fields = body.fields(&decoded_views, &extensions)?;
		let plan = PlanBody::new(fields)?;
		if plan.digest() != expected {
			return Err(PlanError::Integrity.into());
		}
		Ok(Self {
			canonical: plan.canonical_cbor().to_vec(),
			digest: expected,
		})
	}

	/// Returns a checked view borrowing the owned canonical body.
	///
	/// # Errors
	/// Propagates the canonical body decoder's validation failures.
	pub fn body(&self) -> Result<PlanBody<'_>, PlanError> {
		PlanBody::from_canonical_cbor(self.digest, &self.canonical)
	}

	/// Returns the exact canonical CBOR bytes covered by the declared digest.
	#[must_use]
	pub fn canonical_cbor(&self) -> &[u8] {
		&self.canonical
	}

	/// Returns the checked BLAKE3-256 public Plan body digest.
	#[must_use]
	pub const fn digest(&self) -> [u8; 32] {
		self.digest
	}

	/// Emits a bounded unsigned JSON envelope with UTC timestamps.
	///
	/// # Errors
	/// Rejects a failed body revalidation or an output exceeding the JSON limit.
	pub fn to_json(&self) -> Result<Vec<u8>, PlanJsonError> {
		let body = self.body()?;
		let extensions = extensions::to_json(body.fields().extensions)?;
		let body = schema::Body::from_fields(body.fields(), &extensions)?;
		limits::to_json(&Envelope {
			body: limits::Object(body),
			digest: schema::hex(self.digest),
			approval: None,
		})
	}
}

impl core::fmt::Debug for PublicPlan {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("PublicPlan")
			.field("digest", &self.digest)
			.finish_non_exhaustive()
	}
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'input> {
	#[serde(borrow)]
	body: limits::Object<schema::Body<'input>>,
	digest: String,
	#[serde(
		borrow,
		default,
		deserialize_with = "present",
		skip_serializing_if = "Option::is_none"
	)]
	approval: Option<&'input RawValue>,
}

fn present<'de, D: serde::Deserializer<'de>>(
	deserializer: D,
) -> Result<Option<&'de RawValue>, D::Error> {
	<&RawValue>::deserialize(deserializer).map(Some)
}
