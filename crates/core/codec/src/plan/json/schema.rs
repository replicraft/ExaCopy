use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use uuid::Uuid;

use crate::{DocumentPageKind, DocumentRef};

use super::super::{
	MAX_GRANTS, MAX_PAGES, MAX_ROOTS, MAX_SOURCE_VIEWS, PlanBodyFields, PlanError, PlanExtensions,
	PlanOperation, PlanResourceLimits, PlanSourceView, UnixTimestamp,
};
use super::limits::{Items, Object, nullable};
use super::{PlanJsonError, VERSION, datetime};

mod evidence;
mod names;
mod number;
mod policy;

use evidence::SourceView;
pub(super) use evidence::{DecodedIdentity, decode_views};
use names::WireName;
use policy::Policy;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Body<'input> {
	pub(super) schema_version: String,
	plan_id: String,
	operation: String,
	created_at: String,
	#[serde(deserialize_with = "nullable")]
	expires_at: Option<String>,
	source_roots: Items<String, MAX_ROOTS>,
	destination_root: String,
	entry_pages: Items<Object<PageRef>, MAX_PAGES>,
	policy: Object<Policy>,
	resource_limits: Object<ResourceLimits>,
	approval_required: bool,
	pub(super) source_views: Items<Object<SourceView>, MAX_SOURCE_VIEWS>,
	required_grants: Items<String, MAX_GRANTS>,
	estimated_working_bytes: String,
	conflict_count: String,
	entry_count: String,
	complete: bool,
	#[serde(borrow)]
	pub(super) extensions: &'input RawValue,
}

impl<'input> Body<'input> {
	pub(super) fn fields<'body>(
		&'body self,
		decoded: &'body [Option<DecodedIdentity>],
		extensions: &'body [u8],
	) -> Result<PlanBodyFields<'body>, PlanJsonError> {
		let source_roots = self
			.source_roots
			.0
			.iter()
			.map(|text| uuid(text))
			.collect::<Result<_, _>>()?;
		let entry_pages = self
			.entry_pages
			.0
			.iter()
			.map(|Object(entry)| entry.as_reference())
			.collect::<Result<_, _>>()?;
		let source_views: Vec<PlanSourceView<'body>> = self
			.source_views
			.0
			.iter()
			.zip(decoded)
			.map(|(Object(view), identity)| view.as_view(identity.as_ref()))
			.collect::<Result<_, _>>()?;
		Ok(PlanBodyFields {
			plan_id: uuid(&self.plan_id)?,
			operation: PlanOperation::parse(&self.operation)?,
			created_at: datetime::parse(&self.created_at)?,
			expires_at: optional_time(self.expires_at.as_deref())?,
			source_roots,
			destination_root: uuid(&self.destination_root)?,
			entry_pages,
			policy: self.policy.0.as_policy()?,
			resource_limits: self.resource_limits.0.as_limits()?,
			approval_required: self.approval_required,
			source_views,
			required_grants: self.required_grants.0.iter().map(String::as_str).collect(),
			estimated_working_bytes: unsigned(&self.estimated_working_bytes)?,
			conflict_count: unsigned(&self.conflict_count)?,
			entry_count: unsigned(&self.entry_count)?,
			complete: self.complete,
			extensions: PlanExtensions::from_canonical_cbor(extensions)?,
		})
	}

	pub(super) fn from_fields(
		fields: &PlanBodyFields<'_>,
		extensions: &'input RawValue,
	) -> Result<Self, PlanJsonError> {
		let source_views = fields
			.source_views
			.iter()
			.map(|view| SourceView::from_view(view).map(Object))
			.collect::<Result<_, _>>()?;
		Ok(Self {
			schema_version: VERSION.to_owned(),
			plan_id: fields.plan_id.to_string(),
			operation: fields.operation.name().to_owned(),
			created_at: datetime::format(fields.created_at)?,
			expires_at: fields.expires_at.map(datetime::format).transpose()?,
			source_roots: Items(fields.source_roots.iter().map(Uuid::to_string).collect()),
			destination_root: fields.destination_root.to_string(),
			entry_pages: Items(
				fields
					.entry_pages
					.iter()
					.map(|page| Object(PageRef::from(*page)))
					.collect(),
			),
			policy: Object(Policy::from(fields.policy)),
			resource_limits: Object(ResourceLimits::from(fields.resource_limits)),
			approval_required: fields.approval_required,
			source_views: Items(source_views),
			required_grants: Items(
				fields
					.required_grants
					.iter()
					.map(|grant| (*grant).to_owned())
					.collect(),
			),
			estimated_working_bytes: fields.estimated_working_bytes.to_string(),
			conflict_count: fields.conflict_count.to_string(),
			entry_count: fields.entry_count.to_string(),
			complete: fields.complete,
			extensions,
		})
	}
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PageRef {
	page_id: String,
	page_kind: String,
	encoded_bytes: String,
	entry_count: String,
}

impl PageRef {
	fn as_reference(&self) -> Result<DocumentRef, PlanJsonError> {
		DocumentRef::new(
			digest(&self.page_id)?,
			DocumentPageKind::parse(&self.page_kind)?,
			unsigned(&self.encoded_bytes)?,
			unsigned(&self.entry_count)?,
		)
		.map_err(|error| PlanError::from(error).into())
	}
}

impl From<DocumentRef> for PageRef {
	fn from(reference: DocumentRef) -> Self {
		Self {
			page_id: hex(reference.page_id()),
			page_kind: reference.kind().name().to_owned(),
			encoded_bytes: reference.encoded_bytes().to_string(),
			entry_count: reference.item_count().to_string(),
		}
	}
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceLimits {
	buffer_budget_bytes: String,
	#[serde(deserialize_with = "number::deserialize")]
	io_inflight_max: u8,
}

impl ResourceLimits {
	fn as_limits(&self) -> Result<PlanResourceLimits, PlanJsonError> {
		Ok(PlanResourceLimits::new(
			unsigned(&self.buffer_budget_bytes)?,
			self.io_inflight_max,
		)?)
	}
}

impl From<PlanResourceLimits> for ResourceLimits {
	fn from(limits: PlanResourceLimits) -> Self {
		Self {
			buffer_budget_bytes: limits.buffer_budget_bytes().to_string(),
			io_inflight_max: limits.io_inflight_max(),
		}
	}
}

pub(super) fn digest(text: &str) -> Result<[u8; 32], PlanJsonError> {
	if text.len() != 64
		|| !text
			.bytes()
			.all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
	{
		return Err(PlanJsonError::Digest);
	}
	blake3::Hash::from_hex(text)
		.map(|hash| *hash.as_bytes())
		.map_err(|_| PlanJsonError::Digest)
}

pub(super) fn hex(bytes: [u8; 32]) -> String {
	blake3::Hash::from_bytes(bytes).to_hex().to_string()
}

fn unsigned(text: &str) -> Result<u64, PlanJsonError> {
	let bytes = text.as_bytes();
	if bytes.is_empty()
		|| bytes.len() > 20
		|| (bytes.len() > 1 && bytes[0] == b'0')
		|| !bytes.iter().all(u8::is_ascii_digit)
	{
		return Err(PlanJsonError::Integer);
	}
	text.parse().map_err(|_| PlanJsonError::Integer)
}

fn uuid(text: &str) -> Result<Uuid, PlanJsonError> {
	if text.len() != 36 {
		return Err(PlanJsonError::Identifier);
	}
	let id = Uuid::parse_str(text).map_err(|_| PlanJsonError::Identifier)?;
	if !id
		.hyphenated()
		.encode_lower(&mut [0; 36])
		.eq_ignore_ascii_case(text)
	{
		return Err(PlanJsonError::Identifier);
	}
	Ok(id)
}

fn optional_time(text: Option<&str>) -> Result<Option<UnixTimestamp>, PlanJsonError> {
	text.map(datetime::parse).transpose()
}
