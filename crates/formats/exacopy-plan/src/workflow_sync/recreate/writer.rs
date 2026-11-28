use super::super::projection::write_object;
use super::super::wire::is_record_id;
use super::super::writer::{self, MAX_BODY_BYTES, WriteError, Writer};
use super::super::{MAX_MEMBER_BYTES, WorkflowError as Error};
use super::{
	ACTION_PAGE_KIND, ACTION_PAGE_VERSION, OBSERVATION_DOMAIN, PARENT_KIND, REQUIRED_FEATURES,
	RecreateAction, RecreateActionRef, RecreateObservation, RecreateParent, RecreateSide, VERSION,
	decode_parent, validate_action, validate_references, validate_times_and_pair,
};
use crate::UnixTimestamp;

/// Encodes one canonical review-only kind-5 parent body.
///
/// # Errors
/// Refuses invalid identifiers, references, coverage or time bounds.
pub fn encode_parent(value: &RecreateParent) -> Result<Vec<u8>, Error> {
	writer::validate_header(value.id, value.profile)?;
	validate_references(value.endpoints, value.predecessor, value.action_page)?;
	validate_times_and_pair(
		value.pair_id,
		value.created_at,
		value.expires_at,
		value.coverage,
	)?;
	let mut buffer = [0; MAX_BODY_BYTES];
	let bytes = writer::bounded(&mut buffer, |out| {
		writer::header(
			out,
			VERSION,
			PARENT_KIND,
			REQUIRED_FEATURES,
			value.id,
			value.profile,
		)?;
		out.map(14)?.u8(0)?.bytes(&value.pair_id)?.u8(1)?.array(2)?;
		for endpoint in value.endpoints {
			writer::reference(out, endpoint)?;
		}
		out.u8(2)?;
		writer::reference(out, value.predecessor)?;
		out.u8(3)?
			.bytes(&value.filter)?
			.u8(4)?
			.bytes(&value.policy)?
			.u8(5)?
			.u8(3)?
			.u8(6)?
			.u8(2)?
			.u8(7)?
			.array(2)?;
		for digest in &value.coverage {
			out.map(3)?
				.u8(0)?
				.bool(true)?
				.u8(1)?
				.bytes(digest)?
				.u8(2)?
				.array(0)?;
		}
		out.u8(8)?.array(1)?;
		action_ref(out, value.action_page)?;
		out.u8(9)?
			.u8(1)?
			.u8(10)?
			.u8(0)?
			.u8(11)?
			.array(0)?
			.u8(12)?
			.bool(true)?
			.u8(13)?;
		time(out, value.expires_at)?;
		out.u8(6)?;
		time(out, value.created_at)?;
		out.u8(7)?.u8(1)?;
		Ok(())
	})?;
	Ok(bytes.to_vec())
}

/// Frames a canonical parent body and a detached signature without trusting the signer.
///
/// # Errors
/// Refuses unsupported body syntax or an envelope outside the member limit.
pub fn encode_parent_envelope(
	body: &[u8],
	public_key: [u8; 32],
	signature: [u8; 64],
) -> Result<Vec<u8>, Error> {
	decode_parent(body)?;
	writer::envelope(body, public_key, signature)
}

/// Encodes the singleton create-new action page without effect authority.
///
/// # Errors
/// Refuses invalid action identifiers, child references or extents.
pub fn encode_action(value: &RecreateAction<'_>) -> Result<Vec<u8>, Error> {
	let child_page_bytes = validate_action(value)?;
	let mut buffer = [0; MAX_MEMBER_BYTES];
	let bytes = writer::bounded(&mut buffer, |out| {
		out.map(6)?
			.u8(0)?
			.array(2)?
			.u64(ACTION_PAGE_VERSION[0])?
			.u64(ACTION_PAGE_VERSION[1])?
			.u8(1)?
			.u16(ACTION_PAGE_KIND)?
			.u8(2)?
			.u8(0)?
			.u8(3)?
			.array(1)?
			.map(13)?
			.u8(0)?
			.bytes(&value.id)?
			.u8(1)?
			.u8(value.side as u8)?
			.u8(2)?;
		writer::component(out, value.name)?;
		out.u8(3)?.u8(1)?.u8(4)?;
		write_object(out, value.source)?;
		out.u8(5)?
			.null()?
			.u8(6)?
			.u8(2)?
			.u8(7)?
			.u8(1)?
			.u8(8)?
			.map(4)?
			.u8(0)?
			.u64(value.stream_length)?
			.u8(1)?
			.bytes(&value.stream_digest)?
			.u8(2)?
			.bytes(&value.metadata_digest)?
			.u8(3)?;
		writer::reference_fields(
			out,
			value.child_page.page_id(),
			value.child_page.kind() as u16,
			child_page_bytes,
		)?;
		out.u8(9)?
			.bytes(&value.child_digest)?
			.u8(10)?
			.null()?
			.u8(11)?
			.u8(value.reason as u8)?
			.u8(12)?
			.u8(0)?
			.u8(4)?
			.array(0)?
			.u8(5)?
			.u8(1)?;
		Ok(())
	})?;
	Ok(bytes.to_vec())
}

/// Computes domain-separated one-subject observation digests in left/right order.
///
/// The caller supplies independently selected policy and authenticated predecessor facts.
/// # Errors
/// Refuses an invalid pair identifier or improperly typed or sized references.
pub fn observation_digests(value: &RecreateObservation) -> Result<[[u8; 32]; 2], Error> {
	if !is_record_id(value.pair_id) {
		return Err(Error::Shape);
	}
	validate_references(value.endpoints, value.predecessor, value.action_page)?;
	Ok([
		observation_digest(value, RecreateSide::Left)?,
		observation_digest(value, RecreateSide::Right)?,
	])
}

fn observation_digest(value: &RecreateObservation, side: RecreateSide) -> Result<[u8; 32], Error> {
	let mut buffer = [0; MAX_MEMBER_BYTES];
	let bytes = writer::bounded(&mut buffer, |out| {
		out.array(8)?
			.u8(side as u8)?
			.bytes(&value.pair_id)?
			.bytes(&value.predecessor_pair)?
			.array(2)?;
		for endpoint in value.endpoints {
			writer::reference(out, endpoint)?;
		}
		writer::reference(out, value.predecessor)?;
		out.bytes(&value.scope)?.bytes(&value.policy_pin)?;
		action_ref(out, value.action_page)
	})?;
	Ok(*blake3::Hasher::new()
		.update(OBSERVATION_DOMAIN)
		.update(bytes)
		.finalize()
		.as_bytes())
}

fn action_ref(out: &mut Writer<'_>, value: RecreateActionRef) -> Result<(), WriteError> {
	writer::reference_fields(out, value.digest, ACTION_PAGE_KIND, value.byte_len)
}

fn time(out: &mut Writer<'_>, value: UnixTimestamp) -> Result<(), WriteError> {
	out.array(2)?
		.i64(value.seconds())?
		.u32(value.nanoseconds())?;
	Ok(())
}
