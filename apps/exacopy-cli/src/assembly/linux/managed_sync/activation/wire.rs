//! Fixed-width detached bodies rebuilt from independently selected facts.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use exacopy_journal::managed_action_prepared::MANAGED_ACTION_PREPARED_FRAME_BYTES;
use exacopy_model::{JobId, SyncConflict, SyncSide};
use exacopy_plan::UnixTimestamp;
use exacopy_platform::linux::FileIdentity;

use crate::sync_preview::managed_ack::profile_path_digest;
use crate::sync_preview::managed_policy::ManagedPolicyPin;

use super::super::ManualRecreateCandidate;
use super::{ApprovalArtifacts, ApprovalError as Error, ApprovalOperation, ApprovalSelection};

const HOST_MAGIC: &[u8; 8] = b"EXMAH001";
const GRANT_MAGIC: &[u8; 8] = b"EXMAG001";
const PARENT_MAGIC: &[u8; 8] = b"EXMAE001";
const ACTIVATION_MAGIC: &[u8; 8] = b"EXMAA001";
const VERSION_MAJOR: u8 = 1;
const VERSION_MINOR: u8 = 0;
const REQUIRED_FEATURES: u16 = 0;
const HOST_DOMAIN: &str = "ExaCopy Linux managed approval host selection v1";
const GRANT_DOMAIN: &str = "ExaCopy Linux managed approval scoped grant v1";
const PARENT_DOMAIN: &str = "ExaCopy Linux managed approval executable parent v1";
const BODY_DOMAIN: &str = "ExaCopy Linux managed activation unsigned body v1";
const ENVELOPE_DOMAIN: &str = "ExaCopy Linux managed activation signed envelope v1";
const SIGNING_PURPOSE: &[u8] = b"ExaCopy/linux-managed-activation/v1\0";

const HEADER_BYTES: usize = 12;
const HOST_BYTES: usize = HEADER_BYTES + 15 * 16 + 15 * 32 + 7 * 8 + 4 * 12 + 2;
const GRANT_BYTES: usize = HEADER_BYTES + 7 * 32 + 16 + 2 * 8 + 2 * 12 + 1;
const PARENT_BYTES: usize = HEADER_BYTES + 7 * 32 + 2 * 16;
const BODY_BYTES: usize = HEADER_BYTES + 4 * 32 + 2 * 16 + 2 * 12;
const SIGNATURE_BYTES: usize = 64;
const ENVELOPE_BYTES: usize = BODY_BYTES + SIGNATURE_BYTES;
const PREPARED_ORIGIN_BYTES: u64 = MANAGED_ACTION_PREPARED_FRAME_BYTES as u64;
const FIRST_GENERATION: u64 = 1;

const SLOT_DOMAIN: &str = "ExaCopy Linux managed action slot identity v1";
const SEGMENT_DOMAIN: &str = "ExaCopy Linux managed action segment identity v1";

pub(super) fn role_projections(slot: &[u8], segment: &[u8]) -> [[u8; 32]; 2] {
	[
		blake3::derive_key(SLOT_DOMAIN, slot),
		blake3::derive_key(SEGMENT_DOMAIN, segment),
	]
}

pub(super) fn host(
	selected: &ApprovalSelection<'_>,
	pin: &ManagedPolicyPin,
	profile: FileIdentity,
	owner: &VerifyingKey,
) -> Result<(Vec<u8>, [u8; 32]), Error> {
	let (review, enrollment) = (selected.review, selected.enrollment);
	let identity = &pin.identity;
	let approver = enrollment.approver;
	let qualification = enrollment.qualification;
	let attestor = qualification.attestor_key;
	let (ordinary_profile, ordinary_key) = enrollment.ordinary_owner;
	let [from, until] = enrollment.window;
	let conflict = match (review.from, review.conflict) {
		(side, SyncConflict::DeletionAgainstUnchanged { absent }) if side != absent => 0,
		(side, SyncConflict::EditAgainstDeletion { edited }) if side == edited => 1,
		_ => return Err(Error::Selection),
	};
	if !approval_keys_match(owner, ordinary_key, approver, attestor)
		|| ordinary_profile.as_bytes() != &identity.owner_profile
		|| JobId::try_from_bytes(review.pair).is_err()
		|| JobId::try_from_bytes(review.parent).is_err()
		|| review.ids.plan.is_nil()
		|| review.ids.entry.is_nil()
		|| review.ids.source_view.is_nil()
		|| review.ids.measurement.is_nil()
		|| [
			enrollment.origin_ids[0],
			enrollment.origin_ids[1],
			enrollment.activation,
			review.action,
			qualification.attestor_id,
			*enrollment.attempt.entry.as_bytes(),
		]
		.contains(&[0; 16])
		|| enrollment.origin_ids[0] == enrollment.origin_ids[1]
		|| enrollment.attempt.epoch.get() == 0
		|| enrollment.role_projections[0] == enrollment.role_projections[1]
		|| enrollment.prepared.sequence() != 1
		|| enrollment.prepared_extent != PREPARED_ORIGIN_BYTES
		|| [
			enrollment.current_selection,
			enrollment.predecessor,
			review.parent_digest,
			review.child_digest,
			*enrollment.private_plan.as_bytes(),
			enrollment.prepared.digest(),
			enrollment.role_projections[0],
			enrollment.role_projections[1],
			*qualification.record_digest.as_bytes(),
		]
		.contains(&[0; 32])
		|| review.ids.observed_at > from
		|| from >= until
		|| until > review.expires_at
	{
		return Err(Error::Selection);
	}
	let profile_path = profile_path_digest(selected.profile.path).map_err(|_| Error::Selection)?;
	let qualification_path =
		profile_path_digest(qualification.record_path).map_err(|_| Error::Selection)?;
	Ok(encode_host(HostFields {
		ids: [
			identity.selection_id,
			identity.owner_profile,
			review.pair,
			review.parent,
			review.action,
			*review.ids.plan.as_bytes(),
			*review.ids.entry.as_bytes(),
			*review.ids.source_view.as_bytes(),
			*review.ids.measurement.as_bytes(),
			enrollment.origin_ids[0],
			enrollment.origin_ids[1],
			enrollment.activation,
			*enrollment.attempt.job.as_bytes(),
			*enrollment.attempt.entry.as_bytes(),
			qualification.attestor_id,
		],
		digests: [
			identity.owner_key,
			approver.to_bytes(),
			attestor.to_bytes(),
			profile_path,
			qualification_path,
			pin.digest,
			enrollment.current_selection,
			enrollment.predecessor,
			review.parent_digest,
			review.child_digest,
			*enrollment.private_plan.as_bytes(),
			enrollment.role_projections[0],
			enrollment.role_projections[1],
			enrollment.prepared.digest(),
			*qualification.record_digest.as_bytes(),
		],
		counters: [
			identity.revision.get(),
			profile.device(),
			profile.inode(),
			FIRST_GENERATION,
			enrollment.attempt.epoch.get(),
			enrollment.prepared.sequence(),
			enrollment.prepared_extent,
		],
		times: [review.ids.observed_at, review.expires_at, from, until],
		direction: side(review.from),
		reason: conflict,
	}))
}

struct HostFields {
	ids: [[u8; 16]; 15],
	digests: [[u8; 32]; 15],
	counters: [u64; 7],
	times: [UnixTimestamp; 4],
	direction: u8,
	reason: u8,
}

fn encode_host(fields: HostFields) -> (Vec<u8>, [u8; 32]) {
	let mut bytes = header(HOST_MAGIC, HOST_BYTES);
	for field in fields.ids {
		bytes.extend(field);
	}
	for field in fields.digests {
		bytes.extend(field);
	}
	for value in fields.counters {
		bytes.extend(value.to_le_bytes());
	}
	for value in fields.times {
		timestamp(&mut bytes, value);
	}
	bytes.extend([fields.direction, fields.reason]);
	assert_eq!(bytes.len(), HOST_BYTES);
	let digest = blake3::derive_key(HOST_DOMAIN, &bytes);
	(bytes, digest)
}

pub(super) fn approve(
	selected: &ApprovalSelection<'_>,
	host: [u8; 32],
	p063_pair: [u8; 32],
	observed: &ManualRecreateCandidate,
	buffer_budget: u64,
	operation: ApprovalOperation<'_>,
) -> Result<ApprovalArtifacts, Error> {
	let review = selected.review;
	let enrollment = selected.enrollment;
	approve_fields(
		ApprovalFields {
			host,
			review: review.parent_digest,
			child: review.child_digest,
			private_plan: *enrollment.private_plan.as_bytes(),
			content: observed.source.content_digest,
			metadata: observed.source.required_metadata_digest,
			qualification: *enrollment.qualification.record_digest.as_bytes(),
			action: review.action,
			stream_length: observed.source.byte_len,
			buffer_budget,
			window: enrollment.window,
			direction: side(review.from),
			predecessor: enrollment.predecessor,
			p063_pair,
			pair: review.pair,
			activation: enrollment.activation,
			approver: enrollment.approver,
		},
		operation,
	)
}

struct ApprovalFields<'key> {
	host: [u8; 32],
	review: [u8; 32],
	child: [u8; 32],
	private_plan: [u8; 32],
	content: [u8; 32],
	metadata: [u8; 32],
	qualification: [u8; 32],
	action: [u8; 16],
	stream_length: u64,
	buffer_budget: u64,
	window: [UnixTimestamp; 2],
	direction: u8,
	predecessor: [u8; 32],
	p063_pair: [u8; 32],
	pair: [u8; 16],
	activation: [u8; 16],
	approver: &'key VerifyingKey,
}

fn approve_fields(
	fields: ApprovalFields<'_>,
	operation: ApprovalOperation<'_>,
) -> Result<ApprovalArtifacts, Error> {
	let mut grant = header(GRANT_MAGIC, GRANT_BYTES);
	for field in [
		fields.host,
		fields.review,
		fields.child,
		fields.private_plan,
		fields.content,
		fields.metadata,
		fields.qualification,
	] {
		grant.extend(field);
	}
	grant.extend(fields.action);
	grant.extend(fields.stream_length.to_le_bytes());
	grant.extend(fields.buffer_budget.to_le_bytes());
	for time in fields.window {
		timestamp(&mut grant, time);
	}
	grant.push(fields.direction);
	assert_eq!(grant.len(), GRANT_BYTES);
	let grant_digest = blake3::derive_key(GRANT_DOMAIN, &grant);

	let mut parent = header(PARENT_MAGIC, PARENT_BYTES);
	for field in [
		fields.host,
		grant_digest,
		fields.review,
		fields.predecessor,
		fields.p063_pair,
		fields.child,
		fields.private_plan,
	] {
		parent.extend(field);
	}
	parent.extend(fields.pair);
	parent.extend(fields.action);
	assert_eq!(parent.len(), PARENT_BYTES);
	let parent_digest = blake3::derive_key(PARENT_DOMAIN, &parent);
	if [grant_digest, parent_digest].contains(&[0; 32]) || parent_digest == fields.review {
		return Err(Error::Artifact);
	}

	let mut body = header(ACTIVATION_MAGIC, BODY_BYTES);
	body.extend(fields.activation);
	body.extend(fields.action);
	for field in [fields.host, grant_digest, parent_digest, fields.review] {
		body.extend(field);
	}
	for time in fields.window {
		timestamp(&mut body, time);
	}
	assert_eq!(body.len(), BODY_BYTES);
	let body_digest = blake3::derive_key(BODY_DOMAIN, &body);
	let approver = fields.approver;
	let activation = match operation {
		ApprovalOperation::Preview => None,
		ApprovalOperation::Sign {
			confirmed_body,
			signer,
		} => {
			if confirmed_body != body_digest {
				return Err(Error::Selection);
			}
			let envelope = produce(&body, signer, approver)?;
			let digest = blake3::derive_key(ENVELOPE_DOMAIN, &envelope);
			verify(&body, &envelope, digest, approver)?;
			Some((envelope, digest))
		}
		ApprovalOperation::Verify {
			grant: input_grant,
			parent: input_parent,
			activation,
			activation_digest,
		} => {
			if input_grant != grant.as_slice() || input_parent != parent.as_slice() {
				return Err(Error::Artifact);
			}
			verify(&body, activation, activation_digest, approver)?;
			Some((activation.to_vec(), activation_digest))
		}
	};
	Ok(ApprovalArtifacts {
		grant,
		parent,
		body_digest,
		activation,
	})
}

fn produce(body: &[u8], signer: &SigningKey, approver: &VerifyingKey) -> Result<Vec<u8>, Error> {
	if signer.verifying_key() != *approver {
		return Err(Error::Signature);
	}
	let signature = signer
		.try_sign(&signing_input(body))
		.map_err(|_| Error::Signature)?;
	let mut exact = Vec::with_capacity(ENVELOPE_BYTES);
	exact.extend_from_slice(body);
	exact.extend(signature.to_bytes());
	Ok(exact)
}

fn verify(
	body: &[u8],
	envelope: &[u8],
	expected: [u8; 32],
	approver: &VerifyingKey,
) -> Result<(), Error> {
	if envelope.len() != ENVELOPE_BYTES {
		return Err(Error::Artifact);
	}
	let (recorded, signature) = envelope.split_at(BODY_BYTES);
	if recorded != body
		|| expected == [0; 32]
		|| blake3::derive_key(ENVELOPE_DOMAIN, envelope) != expected
	{
		return Err(Error::Artifact);
	}
	let signature = Signature::from_slice(signature).map_err(|_| Error::Artifact)?;
	approver
		.verify_strict(&signing_input(recorded), &signature)
		.map_err(|_| Error::Signature)
}

fn header(magic: &[u8; 8], capacity: usize) -> Vec<u8> {
	let mut bytes = Vec::with_capacity(capacity);
	bytes.extend_from_slice(magic);
	bytes.extend([VERSION_MAJOR, VERSION_MINOR]);
	bytes.extend(REQUIRED_FEATURES.to_le_bytes());
	bytes
}

fn signing_input(body: &[u8]) -> Vec<u8> {
	[SIGNING_PURPOSE, body].concat()
}

fn approval_keys_match(
	owner: &VerifyingKey,
	ordinary: &VerifyingKey,
	approver: &VerifyingKey,
	attestor: &VerifyingKey,
) -> bool {
	ordinary == owner
		&& approver != owner
		&& attestor != owner
		&& approver != attestor
		&& canonical(approver)
		&& canonical(attestor)
}

fn canonical(key: &VerifyingKey) -> bool {
	!key.is_weak() && key.to_edwards().compress().as_bytes() == key.as_bytes()
}

fn timestamp(bytes: &mut Vec<u8>, value: UnixTimestamp) {
	bytes.extend(value.seconds().to_le_bytes());
	bytes.extend(value.nanoseconds().to_le_bytes());
}

fn side(value: SyncSide) -> u8 {
	match value {
		SyncSide::Left => 0,
		SyncSide::Right => 1,
	}
}

#[cfg(test)]
mod tests;
