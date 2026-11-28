use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::frame::ChainHead;

use super::selection::check_selection;
use super::state::RangePosition;
use super::{
	MAX_PREPARED_BYTES, RANGE_BYTES, WindowsCaptureError, WindowsCaptureRoles,
	WindowsCaptureSelection,
};

const PREPARED_DOMAIN: &[u8] = b"ExaCopy/windows-ntfs-capture/prepared/v1\0";
const RANGE_DOMAIN: &[u8] = b"ExaCopy/windows-ntfs-capture/range/v1\0";
const VERSION: [u8; 2] = [1, 0];
const SIGNATURE_BYTES: usize = 64;
const PREPARED_FIXED_BYTES: usize = 204;
const EXTENT_START: usize = 194;
const EXTENT_END: usize = 202;
const RANGE_BODY_BYTES: usize = RANGE_BYTES - SIGNATURE_BYTES;
const RANGE_DIGEST_START: usize = RANGE_BODY_BYTES - 32;

pub(super) fn sign_prepared(
	selection: &WindowsCaptureSelection<'_>,
	observed: WindowsCaptureRoles,
	extent: u64,
	signer: &SigningKey,
) -> Result<Vec<u8>, WindowsCaptureError> {
	check_selection(selection, observed, extent)?;
	sign(
		prepared_body(selection, observed, extent)?,
		PREPARED_DOMAIN,
		selection.bootstrap.owner_key(),
		signer,
	)
}

pub(super) fn verify_prepared(
	payload: &[u8],
	selection: &WindowsCaptureSelection<'_>,
	observed: WindowsCaptureRoles,
) -> Result<u64, WindowsCaptureError> {
	if !(PREPARED_FIXED_BYTES + 2 + SIGNATURE_BYTES..=MAX_PREPARED_BYTES).contains(&payload.len()) {
		return Err(WindowsCaptureError::Payload);
	}
	let body = verify(payload, PREPARED_DOMAIN, selection.bootstrap.owner_key())?;
	let extent = u64::from_le_bytes(
		body[EXTENT_START..EXTENT_END]
			.try_into()
			.map_err(|_| WindowsCaptureError::Payload)?,
	);
	check_selection(selection, observed, extent)?;
	if body != prepared_body(selection, observed, extent)?.as_slice() {
		return Err(WindowsCaptureError::Payload);
	}
	Ok(extent)
}

fn prepared_body(
	selection: &WindowsCaptureSelection<'_>,
	observed: WindowsCaptureRoles,
	extent: u64,
) -> Result<Vec<u8>, WindowsCaptureError> {
	let count = u16::try_from(selection.target.len()).map_err(|_| WindowsCaptureError::Payload)?;
	let mut body =
		Vec::with_capacity(PREPARED_FIXED_BYTES + selection.target.len() * 2 + SIGNATURE_BYTES);
	body.extend(VERSION);
	body.extend(selection.bootstrap.owner_digest().as_bytes());
	body.extend(selection.bootstrap.boundary().head().digest());
	body.extend(observed.sibling.file_id());
	body.extend(observed.stage_directory.file_id());
	body.extend(observed.stage_payload.file_id());
	body.extend(selection.source_scope);
	body.extend(selection.invocation);
	body.extend(selection.generation.to_le_bytes());
	body.extend(selection.epoch.to_le_bytes());
	body.extend(extent.to_le_bytes());
	body.extend(count.to_le_bytes());
	body.extend(selection.target.iter().copied().flat_map(u16::to_le_bytes));
	Ok(body)
}

pub(super) fn sign_range(
	prepared: ChainHead,
	previous: ChainHead,
	position: RangePosition,
	digest: [u8; 32],
	key: &VerifyingKey,
	signer: &SigningKey,
) -> Result<Vec<u8>, WindowsCaptureError> {
	sign(
		range_body(prepared, previous, position, digest),
		RANGE_DOMAIN,
		key,
		signer,
	)
}

pub(super) fn verify_range(
	payload: &[u8],
	prepared: ChainHead,
	previous: ChainHead,
	position: RangePosition,
	key: &VerifyingKey,
) -> Result<(), WindowsCaptureError> {
	if payload.len() != RANGE_BYTES {
		return Err(WindowsCaptureError::Payload);
	}
	let body = verify(payload, RANGE_DOMAIN, key)?;
	let digest = body[RANGE_DIGEST_START..]
		.try_into()
		.map_err(|_| WindowsCaptureError::Payload)?;
	if body != range_body(prepared, previous, position, digest).as_slice() {
		return Err(WindowsCaptureError::Payload);
	}
	Ok(())
}

fn range_body(
	prepared: ChainHead,
	previous: ChainHead,
	position: RangePosition,
	digest: [u8; 32],
) -> Vec<u8> {
	let mut body = Vec::with_capacity(RANGE_BYTES);
	body.extend(VERSION);
	body.extend(prepared.digest());
	body.extend(previous.digest());
	body.extend(position.ordinal.to_le_bytes());
	body.extend(position.offset.to_le_bytes());
	body.extend(position.length.to_le_bytes());
	body.extend(digest);
	body
}

fn sign(
	mut body: Vec<u8>,
	domain: &[u8],
	selected: &VerifyingKey,
	signer: &SigningKey,
) -> Result<Vec<u8>, WindowsCaptureError> {
	if signer.verifying_key() != *selected {
		return Err(WindowsCaptureError::Signature);
	}
	let signature = signer
		.try_sign(&[domain, body.as_slice()].concat())
		.map_err(|_| WindowsCaptureError::Signature)?;
	body.extend(signature.to_bytes());
	Ok(body)
}

fn verify<'a>(
	payload: &'a [u8],
	domain: &[u8],
	key: &VerifyingKey,
) -> Result<&'a [u8], WindowsCaptureError> {
	let (body, signature) = payload
		.split_last_chunk::<SIGNATURE_BYTES>()
		.ok_or(WindowsCaptureError::Payload)?;
	key.verify_strict(&[domain, body].concat(), &Signature::from_bytes(signature))
		.map_err(|_| WindowsCaptureError::Signature)?;
	Ok(body)
}
