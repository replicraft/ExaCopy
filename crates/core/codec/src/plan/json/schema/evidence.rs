use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{MAX_PLAN_IDENTITY_BYTES, PlanIdentityPlatform, PlanSourceIdentity};

use super::super::super::{PlanSourceView, PlanViewConsistency};
use super::super::limits::{Object, nullable};
use super::super::{PlanJsonError, datetime};
use super::names::WireName;
use super::{digest, hex, optional_time, uuid};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::plan::json) struct SourceView {
	view_id: String,
	root_id: String,
	consistency: String,
	provider: String,
	measurement_id: String,
	#[serde(deserialize_with = "nullable")]
	source_identity: Option<Object<Identity>>,
	observed_at: String,
	#[serde(deserialize_with = "nullable")]
	snapshot_token_digest: Option<String>,
	#[serde(deserialize_with = "nullable")]
	stable_until: Option<String>,
}

impl SourceView {
	pub(super) fn as_view<'a>(
		&'a self,
		identity: Option<&'a DecodedIdentity>,
	) -> Result<PlanSourceView<'a>, PlanJsonError> {
		Ok(PlanSourceView {
			view_id: uuid(&self.view_id)?,
			root_id: uuid(&self.root_id)?,
			consistency: PlanViewConsistency::parse(&self.consistency)?,
			provider: &self.provider,
			measurement_id: uuid(&self.measurement_id)?,
			source_identity: identity.map(DecodedIdentity::as_identity),
			observed_at: datetime::parse(&self.observed_at)?,
			snapshot_token_digest: self
				.snapshot_token_digest
				.as_deref()
				.map(digest)
				.transpose()?,
			stable_until: optional_time(self.stable_until.as_deref())?,
		})
	}

	pub(super) fn from_view(view: &PlanSourceView<'_>) -> Result<Self, PlanJsonError> {
		Ok(Self {
			view_id: view.view_id.to_string(),
			root_id: view.root_id.to_string(),
			consistency: view.consistency.name().to_owned(),
			provider: view.provider.to_owned(),
			measurement_id: view.measurement_id.to_string(),
			source_identity: view
				.source_identity
				.map(|identity| Object(Identity::from(identity))),
			observed_at: datetime::format(view.observed_at)?,
			snapshot_token_digest: view.snapshot_token_digest.map(hex),
			stable_until: view.stable_until.map(datetime::format).transpose()?,
		})
	}
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Identity {
	platform: String,
	volume_id_base64: String,
	object_id_base64: String,
	#[serde(deserialize_with = "nullable")]
	generation_base64: Option<String>,
}

impl From<PlanSourceIdentity<'_>> for Identity {
	fn from(identity: PlanSourceIdentity<'_>) -> Self {
		Self {
			platform: identity.platform.name().to_owned(),
			volume_id_base64: STANDARD.encode(identity.volume_id),
			object_id_base64: STANDARD.encode(identity.object_id),
			generation_base64: identity
				.generation
				.map(|generation| STANDARD.encode(generation)),
		}
	}
}

pub(in crate::plan::json) struct DecodedIdentity {
	platform: PlanIdentityPlatform,
	volume: Vec<u8>,
	object: Vec<u8>,
	generation: Option<Vec<u8>>,
}

impl DecodedIdentity {
	fn decode(identity: &Identity) -> Result<Self, PlanJsonError> {
		Ok(Self {
			platform: PlanIdentityPlatform::parse(&identity.platform)?,
			volume: atom(&identity.volume_id_base64)?,
			object: atom(&identity.object_id_base64)?,
			generation: identity
				.generation_base64
				.as_deref()
				.map(atom)
				.transpose()?,
		})
	}

	fn as_identity(&self) -> PlanSourceIdentity<'_> {
		PlanSourceIdentity {
			platform: self.platform,
			volume_id: &self.volume,
			object_id: &self.object,
			generation: self.generation.as_deref(),
		}
	}
}

pub(in crate::plan::json) fn decode_views(
	views: &[Object<SourceView>],
) -> Result<Vec<Option<DecodedIdentity>>, PlanJsonError> {
	views
		.iter()
		.map(|Object(view)| {
			view.source_identity
				.as_ref()
				.map(|Object(identity)| DecodedIdentity::decode(identity))
				.transpose()
		})
		.collect()
}

const MAX_BASE64_LEN: usize = MAX_PLAN_IDENTITY_BYTES.div_ceil(3) * 4;

fn atom(text: &str) -> Result<Vec<u8>, PlanJsonError> {
	if text.is_empty() || text.len() > MAX_BASE64_LEN {
		return Err(PlanJsonError::Base64);
	}
	let mut bytes = [0; MAX_PLAN_IDENTITY_BYTES];
	let length = STANDARD
		.decode_slice(text, &mut bytes)
		.map_err(|_| PlanJsonError::Base64)?;
	Ok(bytes[..length].to_vec())
}
