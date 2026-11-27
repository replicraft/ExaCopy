use exacopy_core::UnixComponent;
use minicbor::Encoder;
use minicbor::encode::{
	Error as EncodeError,
	write::{Cursor, EndOfSlice},
};

use super::projection::write_location;
use super::wire::{
	ENDPOINT_REQUIRED_FEATURES, LOCAL_EVIDENCE_VALUES, LOCAL_PROFILE, ROOT_REQUIRED_FEATURES,
	SIGNATURE_DOMAIN_CODE, VERSION,
};
use super::{
	EndpointBody, LOCATION_BOUND, MAX_MEMBER_BYTES, RootBody, WorkflowError, WorkflowKind,
	WorkflowRef, WorkflowTimestamp, local_route_digest, signing_input,
};

#[cfg(test)]
mod tests;

type Writer<'bytes> = Encoder<Cursor<&'bytes mut [u8]>>;
type WriteError = EncodeError<EndOfSlice>;

// Map + four keys + domain code + two fixed byte strings + at most three body-length bytes.
const ENVELOPE_OVERHEAD: usize = 1 + 4 + 2 + (2 + 32) + (2 + 64) + 3;
const MAX_BODY_BYTES: usize = MAX_MEMBER_BYTES - ENVELOPE_OVERHEAD;

/// Canonical endpoint or root body with its fixed record kind.
#[derive(Debug)]
pub struct EncodedWorkflowBody {
	kind: WorkflowKind,
	bytes: Vec<u8>,
}

impl EncodedWorkflowBody {
	/// Exact canonical body bytes, before envelope framing.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Domain-separated bytes authenticated by the selected owner.
	#[must_use]
	pub fn signing_input(&self) -> Vec<u8> {
		signing_input(self.kind, &self.bytes)
	}

	/// Frames a detached signature and computes the reference to this body.
	///
	/// This method encodes bytes. The caller verifies the signature and owner.
	/// # Errors
	/// Reports an envelope outside the fixed member budget.
	pub fn attach_signature(
		&self,
		public_key: [u8; 32],
		signature: [u8; 64],
	) -> Result<EncodedWorkflowRecord, WorkflowError> {
		let mut scratch = [0; MAX_MEMBER_BYTES];
		let bytes = bounded(&mut scratch, |out| {
			out.map(4)?
				.u8(0)?
				.bytes(&self.bytes)?
				.u8(1)?
				.bytes(&public_key)?
				.u8(2)?
				.bytes(&signature)?
				.u8(3)?
				.u64(SIGNATURE_DOMAIN_CODE)?;
			Ok(())
		})?;
		let byte_len = u16::try_from(bytes.len()).map_err(|_| WorkflowError::Size)?;
		let digest = *blake3::hash(&self.signing_input()).as_bytes();
		Ok(EncodedWorkflowRecord {
			bytes: bytes.to_vec(),
			reference: WorkflowRef {
				kind: self.kind,
				digest,
				byte_len,
			},
		})
	}
}

/// Canonical signed-envelope representation and its complete extent.
#[derive(Debug)]
pub struct EncodedWorkflowRecord {
	bytes: Vec<u8>,
	reference: WorkflowRef,
}

impl EncodedWorkflowRecord {
	/// Exact canonical envelope bytes.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Reference whose digest covers the kind and body and whose extent covers the envelope.
	#[must_use]
	pub const fn reference(&self) -> WorkflowRef {
		self.reference
	}
}

/// Encodes one typed local endpoint in its existing P-063 profile.
/// # Errors
/// Refuses malformed identities or an extent outside the profile.
pub fn encode_endpoint_body(
	body: &EndpointBody<'_>,
	timestamp: WorkflowTimestamp,
) -> Result<EncodedWorkflowBody, WorkflowError> {
	validate_header(body.id, body.profile)?;
	let facts = body.facts;
	if [
		facts.endpoint,
		facts.root,
		facts.parent,
		facts.location.boot,
	]
	.contains(&[0; 16])
	{
		return Err(WorkflowError::Shape);
	}
	if facts.max_bytes > crate::portable::MAX_LOGICAL_LENGTH {
		return Err(WorkflowError::Size);
	}
	let mut location = [0; LOCATION_BOUND];
	let location = bounded(&mut location, |out| write_location(out, facts.location))?;
	record_body(WorkflowKind::Endpoint, |out| {
		header(
			out,
			WorkflowKind::Endpoint,
			ENDPOINT_REQUIRED_FEATURES,
			body.id,
			body.profile,
		)?;
		out.map(12)?
			.u8(0)?
			.bytes(&facts.endpoint)?
			.u8(1)?
			.u8(0)?
			.u8(2)?
			.u64(body.revision.get())?
			.u8(3)?
			.null()?
			.u8(4)?
			.bytes(&local_route_digest())?
			.u8(5)?
			.bytes(&facts.root)?
			.u8(6)?
			.bytes(location)?
			.u8(7)?
			.str(LOCAL_PROFILE)?
			.u8(8)?
			.map(8)?;
		for (key, value) in (0u8..).zip(LOCAL_EVIDENCE_VALUES) {
			out.u8(key)?.u64(value)?;
		}
		out.u8(7)?
			.null()?
			.u8(9)?
			.map(2)?
			.u8(0)?
			.bytes(&facts.parent)?
			.u8(1)?
			.array(1)?;
		component(out, facts.name)?;
		out.u8(10)?.map(4)?.u8(0)?.u64(facts.max_bytes)?;
		for key in 1..=3 {
			out.u8(key)?.u8(1)?;
		}
		out.u8(11)?.null()?;
		trailer(out, timestamp)
	})
}

/// Encodes one typed generation-one root in its existing P-063 profile.
/// # Errors
/// Refuses malformed identities and references outside the profile.
pub fn encode_root_body(
	body: &RootBody<'_>,
	timestamp: WorkflowTimestamp,
) -> Result<EncodedWorkflowBody, WorkflowError> {
	validate_header(body.id, body.profile)?;
	for endpoint in body.endpoints {
		validate_reference(endpoint, WorkflowKind::Endpoint)?;
	}
	validate_reference(body.leaf, WorkflowKind::Leaf)?;
	record_body(WorkflowKind::Root, |out| {
		header(
			out,
			WorkflowKind::Root,
			ROOT_REQUIRED_FEATURES,
			body.id,
			body.profile,
		)?;
		out.map(10)?
			.u8(0)?
			.bytes(&body.pair)?
			.u8(1)?
			.u8(1)?
			.u8(2)?
			.null()?
			.u8(3)?
			.array(2)?;
		for endpoint in body.endpoints {
			reference(out, endpoint)?;
		}
		out.u8(4)?
			.map(2)?
			.u8(0)?
			.bytes(&body.filter)?
			.u8(1)?
			.bytes(&body.policy)?
			.u8(5)?
			.map(5)?
			.u8(0)?
			.u8(0)?
			.u8(1)?
			.u8(0)?
			.u8(2)?
			.bytes(&body.scope)?
			.u8(3)?
			.u64(body.scan.get())?
			.u8(4)?;
		component(out, body.name)?;
		out.u8(6)?.array(1)?;
		reference(out, body.leaf)?;
		out.u8(7)?.u8(1)?.u8(8)?.array(0)?.u8(9)?.array(0)?;
		trailer(out, timestamp)
	})
}

fn record_body(
	kind: WorkflowKind,
	write: impl FnOnce(&mut Writer<'_>) -> Result<(), WriteError>,
) -> Result<EncodedWorkflowBody, WorkflowError> {
	let mut scratch = [0; MAX_BODY_BYTES];
	let bytes = bounded(&mut scratch, write)?;
	Ok(EncodedWorkflowBody {
		kind,
		bytes: bytes.to_vec(),
	})
}

fn bounded(
	buffer: &mut [u8],
	write: impl FnOnce(&mut Writer<'_>) -> Result<(), WriteError>,
) -> Result<&[u8], WorkflowError> {
	let mut out = Encoder::new(Cursor::new(&mut *buffer));
	write(&mut out).map_err(|_| WorkflowError::Size)?;
	let bytes = out.into_writer().position();
	buffer.get(..bytes).ok_or(WorkflowError::Size)
}

fn validate_header(id: [u8; 16], profile: [u8; 16]) -> Result<(), WorkflowError> {
	if !super::wire::is_record_id(id) || profile == [0; 16] {
		return Err(WorkflowError::Shape);
	}
	Ok(())
}

fn validate_reference(reference: WorkflowRef, kind: WorkflowKind) -> Result<(), WorkflowError> {
	if reference.kind != kind {
		return Err(WorkflowError::Shape);
	}
	if !(1..=MAX_MEMBER_BYTES).contains(&usize::from(reference.byte_len)) {
		return Err(WorkflowError::Size);
	}
	Ok(())
}

fn header(
	out: &mut Writer<'_>,
	kind: WorkflowKind,
	features: u64,
	id: [u8; 16],
	profile: [u8; 16],
) -> Result<(), WriteError> {
	out.map(8)?
		.u8(0)?
		.map(3)?
		.u8(0)?
		.u64(VERSION[0])?
		.u8(1)?
		.u64(VERSION[1])?
		.u8(2)?
		.u64(features)?
		.u8(1)?
		.u16(kind as u16)?
		.u8(2)?
		.bytes(&id)?
		.u8(3)?
		.bytes(&profile)?
		.u8(4)?
		.null()?
		.u8(5)?;
	Ok(())
}

fn trailer(out: &mut Writer<'_>, timestamp: WorkflowTimestamp) -> Result<(), WriteError> {
	out.u8(6)?;
	timestamp.write(out)?;
	out.u8(7)?.u8(1)?;
	Ok(())
}

fn reference(out: &mut Writer<'_>, reference: WorkflowRef) -> Result<(), WriteError> {
	out.map(4)?
		.u8(0)?
		.bytes(&reference.digest)?
		.u8(1)?
		.u16(reference.kind as u16)?
		.u8(2)?
		.u16(reference.byte_len)?
		.u8(3)?
		.u8(1)?;
	Ok(())
}

fn component(out: &mut Writer<'_>, value: UnixComponent<'_>) -> Result<(), WriteError> {
	out.map(2)?.u8(0)?.u8(1)?.u8(1)?.bytes(value.as_bytes())?;
	Ok(())
}
