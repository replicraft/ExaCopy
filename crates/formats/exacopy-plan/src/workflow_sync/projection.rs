use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use minicbor::Encoder;

use crate::cbor::{BodyBytes, EncodeError, canonical_bytes};

use super::{EndpointFacts, LinuxLocation, NativeObject, WorkflowError};

/// Independently reproducible pair, scope and leaf projections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairProjection {
	/// Selected ordered pair ID.
	pub pair: [u8; 32],
	/// Subject filter digest.
	pub filter: [u8; 32],
	/// Fixed strict comparison policy digest.
	pub policy: [u8; 32],
	/// Ordered native root IDs.
	pub roots: [[u8; 32]; 2],
	/// Native common parent ID.
	pub parent: [u8; 32],
}

/// Exact digest of the fixed local-only route policy.
#[must_use]
pub fn local_route_digest() -> [u8; 32] {
	digest(b"local-only/v1\0", |out| {
		out.null()?;
		Ok(())
	})
}

/// Computes the root-independent native identity projection for a held fact.
#[must_use]
pub fn native_id(boot: [u8; 16], object: NativeObject) -> [u8; 32] {
	digest(b"linux-object/v1\0", |out| {
		out.array(3)?.bytes(&boot)?;
		write_device_and_inode(out, object)
	})
}

/// Checks that two independent endpoint expectations fit the narrow profile
/// and derives the exact pair and leaf projections.
/// # Errors
/// Refuses aliased, invalid or inconsistently scoped endpoints.
pub fn project_pair(
	profile: [u8; 16],
	revision: NonZeroU64,
	subject: UnixComponent<'_>,
	endpoints: [EndpointFacts<'_>; 2],
) -> Result<PairProjection, WorkflowError> {
	let [left, right] = endpoints;
	let a = left.location;
	let b = right.location;
	if profile == [0; 16]
		|| left.parent != right.parent
		|| left.endpoint == right.endpoint
		|| left.root == right.root
		|| left.name == right.name
		|| a.root == b.root
		|| a != (LinuxLocation { root: a.root, ..b })
		|| endpoints.into_iter().any(invalid_endpoint)
	{
		return Err(WorkflowError::Shape);
	}
	let filter = digest(b"filter/v1\0", |out| {
		out.array(1)?
			.map(2)?
			.u8(0)?
			.u8(1)?
			.u8(1)?
			.bytes(subject.as_bytes())?;
		Ok(())
	});
	let policy = digest(b"policy/v1\0", |out| {
		out.array(4)?.u8(0)?.u8(0)?.u8(0)?.u8(0)?;
		Ok(())
	});
	let pair = digest(b"pair/v1\0", |out| {
		out.array(6)?.bytes(&profile)?.u64(revision.get())?;
		for endpoint in endpoints {
			out.array(2)?
				.bytes(&endpoint.endpoint)?
				.bytes(&endpoint.root)?;
		}
		out.bytes(&filter)?.bytes(&policy)?;
		Ok(())
	});
	let roots = endpoints.map(|value| native_id(value.location.boot, value.location.root));
	let parent = native_id(a.boot, a.parent);
	Ok(PairProjection {
		pair,
		filter,
		policy,
		roots,
		parent,
	})
}

fn invalid_endpoint(facts: EndpointFacts<'_>) -> bool {
	let location = facts.location;
	let parent = location.parent;
	let root = location.root;
	[facts.endpoint, facts.root, facts.parent, location.boot].contains(&[0; 16])
		|| facts.parent == facts.root
		|| parent == root
		|| (parent.major, parent.minor) != (root.major, root.minor)
		|| facts.max_bytes > crate::portable::MAX_LOGICAL_LENGTH
}

/// Computes scope over independently selected native locations and exact signed references.
#[must_use]
pub fn scope_digest(
	pair: PairProjection,
	key: [u8; 32],
	children: [[u8; 32]; 2],
	locations: [LinuxLocation; 2],
) -> [u8; 32] {
	digest(b"scope/v1\0", |out| {
		out.array(8)?
			.bytes(&pair.pair)?
			.bytes(&key)?
			.bytes(&children[0])?
			.bytes(&children[1])?
			.bytes(&pair.roots[0])?
			.bytes(&pair.roots[1])?;
		for location in locations {
			out.array(6)?.bytes(&location.boot)?;
			write_object(out, location.mount_namespace)?;
			write_object(out, location.user_namespace)?;
			out.u64(location.mount.get())?;
			write_object(out, location.parent)?;
			write_object(out, location.root)?;
		}
		Ok(())
	})
}

fn write_object(out: &mut Encoder<BodyBytes>, value: NativeObject) -> Result<(), EncodeError> {
	out.array(2)?;
	write_device_and_inode(out, value)
}

fn write_device_and_inode(
	out: &mut Encoder<BodyBytes>,
	value: NativeObject,
) -> Result<(), EncodeError> {
	out.array(2)?
		.u32(value.major)?
		.u32(value.minor)?
		.u64(value.inode.get())?;
	Ok(())
}

fn digest(
	suffix: &[u8],
	write: impl FnOnce(&mut Encoder<BodyBytes>) -> Result<(), EncodeError>,
) -> [u8; 32] {
	*blake3::Hasher::new()
		.update(b"ExaCopy/sync-baseline/")
		.update(suffix)
		.update(&canonical_bytes(write))
		.finalize()
		.as_bytes()
}
