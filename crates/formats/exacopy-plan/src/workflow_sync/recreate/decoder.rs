use super::super::decoder::Canonical;
use super::super::wire;
use super::super::writer::MAX_BODY_BYTES;
use super::super::{MAX_MEMBER_BYTES, WorkflowError as Error, WorkflowKind};
use super::{
	ACTION_PAGE_KIND, ACTION_PAGE_VERSION, PARENT_KIND, REQUIRED_FEATURES, RecreateAction,
	RecreateActionRef, RecreateParent, RecreateReason, RecreateSide, VERSION, validate_action,
	validate_times_and_pair,
};
use crate::{DocumentPageKind, DocumentRef};

/// Decodes exact canonical syntax for one review-only managed recreate parent.
///
/// # Errors
/// Refuses unsupported versions, shapes, bounds, or noncanonical bytes.
pub fn decode_parent(bytes: &[u8]) -> Result<RecreateParent, Error> {
	let mut d = Canonical::new(bytes, MAX_BODY_BYTES)?;
	let (id, profile) = wire::header(&mut d, VERSION, PARENT_KIND, REQUIRED_FEATURES)?;
	d.map(14)?;
	d.key(0)?;
	let pair_id = d.uuid()?;
	d.key(1)?;
	d.array(2)?;
	let endpoints = [
		wire::reference(&mut d, WorkflowKind::Endpoint)?,
		wire::reference(&mut d, WorkflowKind::Endpoint)?,
	];
	d.key(2)?;
	let predecessor = wire::reference(&mut d, WorkflowKind::Root)?;
	d.key(3)?;
	let filter = d.fixed()?;
	d.key(4)?;
	let policy = d.fixed()?;
	d.key(5)?;
	d.key(3)?;
	d.key(6)?;
	d.key(2)?;
	d.key(7)?;
	d.array(2)?;
	let coverage = [coverage(&mut d)?, coverage(&mut d)?];
	d.key(8)?;
	d.array(1)?;
	let (digest, byte_len) = wire::reference_fields(&mut d, ACTION_PAGE_KIND)?;
	d.key(9)?;
	d.key(1)?;
	d.key(10)?;
	d.key(0)?;
	d.key(11)?;
	d.array(0)?;
	d.key(12)?;
	d.expect_true()?;
	d.key(13)?;
	let expires_at = d.time()?;
	let created_at = wire::trailer(d)?;
	validate_times_and_pair(pair_id, created_at, expires_at, coverage)?;
	Ok(RecreateParent {
		id,
		profile,
		pair_id,
		endpoints,
		predecessor,
		filter,
		policy,
		coverage,
		action_page: RecreateActionRef { digest, byte_len },
		created_at,
		expires_at,
	})
}

fn coverage(d: &mut Canonical<'_>) -> Result<[u8; 32], Error> {
	d.map(3)?;
	d.key(0)?;
	d.expect_true()?;
	d.key(1)?;
	let digest = d.fixed()?;
	d.key(2)?;
	d.array(0)?;
	Ok(digest)
}

/// Decodes an exact canonical singleton review-only recreate action page.
///
/// # Errors
/// Refuses unsupported versions, shapes, bounds, or noncanonical bytes.
pub fn decode_action(bytes: &[u8]) -> Result<RecreateAction<'_>, Error> {
	let mut d = Canonical::new(bytes, MAX_MEMBER_BYTES)?;
	d.map(6)?;
	d.key(0)?;
	d.array(2)?;
	d.key(ACTION_PAGE_VERSION[0])?;
	d.key(ACTION_PAGE_VERSION[1])?;
	d.key(1)?;
	d.key(u64::from(ACTION_PAGE_KIND))?;
	d.key(2)?;
	d.key(0)?;
	d.key(3)?;
	d.array(1)?;
	let action = action(&mut d)?;
	d.key(4)?;
	d.array(0)?;
	d.key(5)?;
	d.key(1)?;
	d.finish()?;
	validate_action(&action)?;
	Ok(action)
}

fn action<'name>(d: &mut Canonical<'name>) -> Result<RecreateAction<'name>, Error> {
	d.map(13)?;
	d.key(0)?;
	let id = d.uuid()?;
	d.key(1)?;
	let side = match d.number()? {
		0 => RecreateSide::Left,
		1 => RecreateSide::Right,
		_ => return Err(Error::Shape),
	};
	d.key(2)?;
	let name = d.name()?;
	d.key(3)?;
	d.key(1)?;
	d.key(4)?;
	let source = wire::object(d)?;
	d.key(5)?;
	d.null()?;
	d.key(6)?;
	d.key(2)?;
	d.key(7)?;
	d.key(1)?;
	d.key(8)?;
	d.map(4)?;
	d.key(0)?;
	let stream_length = d.number()?;
	d.key(1)?;
	let stream_digest = d.fixed()?;
	d.key(2)?;
	let metadata_digest = d.fixed()?;
	d.key(3)?;
	let kind = DocumentPageKind::PlanEntries;
	let (digest, byte_len) = wire::reference_fields(d, kind as u16)?;
	let child_page =
		DocumentRef::new(digest, kind, u64::from(byte_len), 1).map_err(|_| Error::Size)?;
	d.key(9)?;
	let child_digest = d.fixed()?;
	d.key(10)?;
	d.null()?;
	d.key(11)?;
	let reason = match d.number()? {
		0 => RecreateReason::DeletionAgainstUnchanged,
		1 => RecreateReason::EditAgainstDeletion,
		_ => return Err(Error::Shape),
	};
	d.key(12)?;
	d.key(0)?;
	Ok(RecreateAction {
		id,
		side,
		name,
		source,
		stream_length,
		stream_digest,
		metadata_digest,
		child_digest,
		child_page,
		reason,
	})
}
