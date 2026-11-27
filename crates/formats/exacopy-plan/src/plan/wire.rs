//! Registered numeric projection for the unsigned Plan v1 body.

use minicbor::data::Type;
use minicbor::encode::Write;
use minicbor::{Decoder, Encoder};
use uuid::Uuid;

use crate::cbor::{BodyBytes, EncodeError, canonical_bytes};
use crate::document::{DocumentRef, expect_key, expect_versioned_map, fixed_bytes};

use super::{
	MAX_GRANTS, MAX_PAGES, MAX_ROOTS, MAX_SOURCE_VIEWS, PlanBodyFields, PlanError, PlanExtensions,
	PlanOperation, PlanPolicy, PlanResourceLimits, PlanSourceView, UnixTimestamp, check_label,
};

const VERSION: [u8; 2] = [1, 0];
const PLAN_FIELDS: u64 = 18;

pub(super) fn encode(body: &PlanBodyFields<'_>) -> Vec<u8> {
	canonical_bytes(|encoder| write_body(encoder, body))
}

fn write_body(
	encoder: &mut Encoder<BodyBytes>,
	body: &PlanBodyFields<'_>,
) -> Result<(), EncodeError> {
	encoder
		.map(PLAN_FIELDS)?
		.u8(0)?
		.array(2)?
		.u8(VERSION[0])?
		.u8(VERSION[1])?
		.u8(1)?
		.bytes(body.plan_id.as_bytes())?
		.u8(2)?
		.u8(body.operation as u8)?
		.u8(3)?;
	body.created_at.write_to(encoder)?;
	encoder.u8(4)?;
	UnixTimestamp::write_optional(body.expires_at, encoder)?;

	encoder.u8(5)?.array(body.source_roots.len() as u64)?;
	for root in &body.source_roots {
		encoder.bytes(root.as_bytes())?;
	}
	encoder
		.u8(6)?
		.bytes(body.destination_root.as_bytes())?
		.u8(7)?
		.array(body.entry_pages.len() as u64)?;
	for reference in &body.entry_pages {
		reference.write_to(encoder)?;
	}

	encoder.u8(8)?;
	body.policy.write_to(encoder)?;
	encoder.u8(9)?;
	body.resource_limits.write_to(encoder)?;
	encoder
		.u8(10)?
		.bool(body.approval_required)?
		.u8(11)?
		.array(body.source_views.len() as u64)?;
	for view in &body.source_views {
		view.write_to(encoder)?;
	}

	encoder.u8(12)?.array(body.required_grants.len() as u64)?;
	for grant in &body.required_grants {
		encoder.str(grant)?;
	}
	encoder
		.u8(13)?
		.u64(body.estimated_working_bytes)?
		.u8(14)?
		.u64(body.conflict_count)?
		.u8(15)?
		.u64(body.entry_count)?
		.u8(16)?
		.bool(body.complete)?
		.u8(127)?;
	if let Err(never) = encoder
		.writer_mut()
		.write_all(body.extensions.as_canonical_cbor())
	{
		match never {}
	}
	Ok(())
}

pub(super) fn decode(input: &[u8]) -> Result<PlanBodyFields<'_>, PlanError> {
	let mut decoder = Decoder::new(input);
	expect_versioned_map(&mut decoder, PLAN_FIELDS, VERSION)?;
	expect_key(&mut decoder, 1)?;
	let plan_id = read_uuid(&mut decoder)?;
	expect_key(&mut decoder, 2)?;
	let operation = PlanOperation::read(&mut decoder)?;
	expect_key(&mut decoder, 3)?;
	let created_at = UnixTimestamp::read_from(&mut decoder)?;
	expect_key(&mut decoder, 4)?;
	let expires_at = read_nullable(&mut decoder, UnixTimestamp::read_from)?;
	expect_key(&mut decoder, 5)?;
	let source_roots = read_items(&mut decoder, MAX_ROOTS, read_uuid)?;
	expect_key(&mut decoder, 6)?;
	let destination_root = read_uuid(&mut decoder)?;
	expect_key(&mut decoder, 7)?;
	let entry_pages = read_items(&mut decoder, MAX_PAGES, |decoder| {
		Ok(DocumentRef::read_from(decoder)?)
	})?;
	expect_key(&mut decoder, 8)?;
	let policy = PlanPolicy::read_from(&mut decoder)?;
	expect_key(&mut decoder, 9)?;
	let resource_limits = PlanResourceLimits::read_from(&mut decoder)?;
	expect_key(&mut decoder, 10)?;
	let approval_required = decoder.bool()?;
	expect_key(&mut decoder, 11)?;
	let source_views = read_items(&mut decoder, MAX_SOURCE_VIEWS, PlanSourceView::read_from)?;
	expect_key(&mut decoder, 12)?;
	let required_grants = read_items(&mut decoder, MAX_GRANTS, |decoder| {
		let grant = decoder.str()?;
		check_label(grant)?;
		Ok(grant)
	})?;
	expect_key(&mut decoder, 13)?;
	let estimated_working_bytes = decoder.u64()?;
	expect_key(&mut decoder, 14)?;
	let conflict_count = decoder.u64()?;
	expect_key(&mut decoder, 15)?;
	let entry_count = decoder.u64()?;
	expect_key(&mut decoder, 16)?;
	let complete = decoder.bool()?;
	expect_key(&mut decoder, 127)?;
	let extensions = PlanExtensions::read_from(&mut decoder)?;
	Ok(PlanBodyFields {
		plan_id,
		operation,
		created_at,
		expires_at,
		source_roots,
		destination_root,
		entry_pages,
		policy,
		resource_limits,
		approval_required,
		source_views,
		required_grants,
		estimated_working_bytes,
		conflict_count,
		entry_count,
		complete,
		extensions,
	})
}

pub(super) fn expect_array(decoder: &mut Decoder<'_>, count: u64) -> Result<(), PlanError> {
	if decoder.array()? == Some(count) {
		Ok(())
	} else {
		Err(PlanError::Malformed)
	}
}

pub(super) fn read_uuid(decoder: &mut Decoder<'_>) -> Result<Uuid, PlanError> {
	Ok(Uuid::from_bytes(fixed_bytes(decoder)?))
}

pub(super) fn read_nullable<'body, T>(
	decoder: &mut Decoder<'body>,
	read: impl FnOnce(&mut Decoder<'body>) -> Result<T, PlanError>,
) -> Result<Option<T>, PlanError> {
	if decoder.datatype()? == Type::Null {
		decoder.null()?;
		Ok(None)
	} else {
		read(decoder).map(Some)
	}
}

fn read_items<'body, T>(
	decoder: &mut Decoder<'body>,
	limit: usize,
	mut read: impl FnMut(&mut Decoder<'body>) -> Result<T, PlanError>,
) -> Result<Vec<T>, PlanError> {
	let count = decoder.array()?.ok_or(PlanError::NonCanonical)?;
	let count = usize::try_from(count).map_err(|_| PlanError::Bounds)?;
	let remaining = decoder.input().len().saturating_sub(decoder.position());
	if count > limit {
		return Err(PlanError::Bounds);
	}
	if count > remaining {
		return Err(PlanError::Malformed);
	}
	let mut items = Vec::with_capacity(count);
	for _ in 0..count {
		items.push(read(decoder)?);
	}
	Ok(items)
}
