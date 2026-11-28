use super::decoder::Canonical;
use super::{
	EndpointBody, EndpointFacts, LOCATION_BOUND, LinuxLocation, MAX_MEMBER_BYTES, NativeObject,
	RootBody, WorkflowEnvelope, WorkflowError as Error, WorkflowKind, WorkflowRef,
	local_route_digest,
};
use crate::UnixTimestamp;

pub(super) const ROOT_REQUIRED_FEATURES: u64 = 69;
pub(super) const ENDPOINT_REQUIRED_FEATURES: u64 = 1;
pub(super) const VERSION: [u64; 2] = [1, 0];
pub(super) const SIGNATURE_DOMAIN_CODE: u64 = 32;
pub(super) const LOCAL_PROFILE: &str = "linux-managed-local-sync-genesis-v1";
pub(super) const LOCAL_EVIDENCE_VALUES: [u64; 7] = [0, 0, 0, 0, 0, 3, 2];

/// Parses the bounded canonical outer envelope only.
/// # Errors
/// Refuses unsupported shapes, excessive lengths and noncanonical bytes.
pub fn decode_envelope(bytes: &[u8]) -> Result<WorkflowEnvelope<'_>, Error> {
	let mut d = Canonical::new(bytes, MAX_MEMBER_BYTES)?;
	d.map(4)?;
	d.key(0)?;
	let body = d.bytes()?;
	d.key(1)?;
	let public_key = d.fixed()?;
	d.key(2)?;
	let signature = d.fixed()?;
	d.key(3)?;
	d.key(SIGNATURE_DOMAIN_CODE)?;
	d.finish()?;
	Ok(WorkflowEnvelope {
		body,
		public_key,
		signature,
	})
}

/// Parses the canonical syntax of one kind-6 root body.
/// # Errors
/// Refuses unsupported versions, fields, references and noncanonical encoding.
pub fn decode_root(bytes: &[u8]) -> Result<RootBody<'_>, Error> {
	let mut d = Canonical::new(bytes, MAX_MEMBER_BYTES)?;
	let (id, profile) = header(
		&mut d,
		VERSION,
		WorkflowKind::Root as u16,
		ROOT_REQUIRED_FEATURES,
	)?;
	d.map(10)?;
	d.key(0)?;
	let pair = d.fixed()?;
	d.key(1)?;
	d.key(1)?;
	d.key(2)?;
	d.null()?;
	d.key(3)?;
	d.array(2)?;
	let endpoints = [
		reference(&mut d, WorkflowKind::Endpoint)?,
		reference(&mut d, WorkflowKind::Endpoint)?,
	];
	d.key(4)?;
	d.map(2)?;
	d.key(0)?;
	let filter = d.fixed()?;
	d.key(1)?;
	let policy = d.fixed()?;
	d.key(5)?;
	d.map(5)?;
	d.key(0)?;
	d.key(0)?;
	d.key(1)?;
	d.key(0)?;
	d.key(2)?;
	let scope = d.fixed()?;
	d.key(3)?;
	let scan = d.positive()?;
	d.key(4)?;
	let name = d.name()?;
	d.key(6)?;
	d.array(1)?;
	let leaf = reference(&mut d, WorkflowKind::Leaf)?;
	d.key(7)?;
	d.key(1)?;
	d.key(8)?;
	d.array(0)?;
	d.key(9)?;
	d.array(0)?;
	trailer(d)?;
	Ok(RootBody {
		id,
		profile,
		pair,
		endpoints,
		filter,
		policy,
		scope,
		scan,
		name,
		leaf,
	})
}

/// Parses the canonical syntax of one kind-1 local endpoint.
/// # Errors
/// Refuses unsupported versions, fields, location and noncanonical encoding.
pub fn decode_endpoint(bytes: &[u8]) -> Result<EndpointBody<'_>, Error> {
	let mut d = Canonical::new(bytes, MAX_MEMBER_BYTES)?;
	let (id, profile) = header(
		&mut d,
		VERSION,
		WorkflowKind::Endpoint as u16,
		ENDPOINT_REQUIRED_FEATURES,
	)?;
	d.map(12)?;
	d.key(0)?;
	let endpoint = d.uuid()?;
	d.key(1)?;
	d.key(0)?;
	d.key(2)?;
	let revision = d.positive()?;
	d.key(3)?;
	d.null()?;
	d.key(4)?;
	if d.fixed::<32>()? != local_route_digest() {
		return Err(Error::Shape);
	}
	d.key(5)?;
	let root = d.uuid()?;
	d.key(6)?;
	let location = read_location(d.bytes()?)?;
	d.key(7)?;
	d.text(LOCAL_PROFILE)?;
	d.key(8)?;
	d.map(8)?;
	for (key, value) in LOCAL_EVIDENCE_VALUES.into_iter().enumerate() {
		d.key(key as u64)?;
		d.key(value)?;
	}
	d.key(7)?;
	d.null()?;
	d.key(9)?;
	d.map(2)?;
	d.key(0)?;
	let parent = d.uuid()?;
	d.key(1)?;
	d.array(1)?;
	let name = d.name()?;
	d.key(10)?;
	d.map(4)?;
	d.key(0)?;
	let max_bytes = d.number()?;
	if max_bytes > crate::portable::MAX_LOGICAL_LENGTH {
		return Err(Error::Size);
	}
	for key in 1..=3 {
		d.key(key)?;
		d.key(1)?;
	}
	d.key(11)?;
	d.null()?;
	trailer(d)?;
	Ok(EndpointBody {
		id,
		profile,
		revision,
		facts: EndpointFacts {
			endpoint,
			root,
			parent,
			name,
			location,
			max_bytes,
		},
	})
}

pub(super) fn header(
	d: &mut Canonical<'_>,
	version: [u64; 2],
	kind: u16,
	features: u64,
) -> Result<([u8; 16], [u8; 16]), Error> {
	d.map(8)?;
	d.key(0)?;
	d.map(3)?;
	d.key(0)?;
	d.key(version[0])?;
	d.key(1)?;
	d.key(version[1])?;
	d.key(2)?;
	d.key(features)?;
	d.key(1)?;
	d.key(u64::from(kind))?;
	d.key(2)?;
	let id = d.uuid()?;
	if !is_record_id(id) {
		return Err(Error::Shape);
	}
	d.key(3)?;
	let profile = d.uuid()?;
	d.key(4)?;
	d.null()?;
	d.key(5)?;
	Ok((id, profile))
}

pub(super) fn is_record_id(id: [u8; 16]) -> bool {
	id[6] >> 4 == 7 && id[8] >> 6 == 2
}

pub(super) fn trailer(mut d: Canonical<'_>) -> Result<UnixTimestamp, Error> {
	d.key(6)?;
	let time = d.time()?;
	d.key(7)?;
	d.key(1)?;
	d.finish()?;
	Ok(time)
}

pub(super) fn reference(d: &mut Canonical<'_>, kind: WorkflowKind) -> Result<WorkflowRef, Error> {
	let (digest, byte_len) = reference_fields(d, kind as u16)?;
	Ok(WorkflowRef {
		digest,
		kind,
		byte_len,
	})
}

pub(super) fn reference_fields(d: &mut Canonical<'_>, kind: u16) -> Result<([u8; 32], u16), Error> {
	d.map(4)?;
	d.key(0)?;
	let digest = d.fixed()?;
	d.key(1)?;
	d.key(u64::from(kind))?;
	d.key(2)?;
	let length = d.number()?;
	if !(1..=MAX_MEMBER_BYTES as u64).contains(&length) {
		return Err(Error::Size);
	}
	d.key(3)?;
	d.key(1)?;
	let byte_len = u16::try_from(length).map_err(|_| Error::Size)?;
	Ok((digest, byte_len))
}

fn read_location(bytes: &[u8]) -> Result<LinuxLocation, Error> {
	let mut d = Canonical::new(bytes, LOCATION_BOUND)?;
	d.array(6)?;
	let location = LinuxLocation {
		boot: d.uuid()?,
		mount_namespace: object(&mut d)?,
		user_namespace: object(&mut d)?,
		mount: d.positive()?,
		parent: object(&mut d)?,
		root: object(&mut d)?,
	};
	d.finish()?;
	Ok(location)
}

pub(super) fn object(d: &mut Canonical<'_>) -> Result<NativeObject, Error> {
	d.array(2)?;
	d.array(2)?;
	let major = u32::try_from(d.number()?).map_err(|_| Error::Shape)?;
	let minor = u32::try_from(d.number()?).map_err(|_| Error::Shape)?;
	let inode = d.positive()?;
	Ok(NativeObject {
		major,
		minor,
		inode,
	})
}
