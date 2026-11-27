//! Canonical workflow syntax and digest projections, without signer admission.

use core::{fmt, num::NonZeroU64};

use exacopy_core::UnixComponent;

mod decoder;
mod projection;
mod wire;
mod writer;

pub use projection::{
	LinuxStability, PairProjection, linux_stability_digest, local_route_digest, native_id,
	project_pair, scope_digest,
};
pub use wire::{decode_endpoint, decode_envelope, decode_root};
pub use writer::{
	EncodedWorkflowBody, EncodedWorkflowRecord, encode_endpoint_body, encode_root_body,
};

/// Maximum bytes per signed workflow member.
pub const MAX_MEMBER_BYTES: usize = 2_048;
/// Maximum combined bytes for root, two endpoints and the observation leaf.
pub const MAX_CLOSURE_BYTES: usize = 8_192;

const RECORD_DOMAIN: &[u8] = b"ExaCopy/workflow-record/v1\0";
const LOCATION_BOUND: usize = 128;

/// Closed artifact kinds of this generation-one profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum WorkflowKind {
	/// Local endpoint binding.
	Endpoint = 1,
	/// Signed genesis projection and member commitments.
	Root = 6,
	/// Paired generation-one Manifest leaf.
	Leaf = 256,
}

/// A syntactically checked commitment to one artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowRef {
	/// Record or page digest in the domain selected by kind.
	pub digest: [u8; 32],
	/// Expected artifact kind.
	pub kind: WorkflowKind,
	/// Exact complete envelope or page bytes.
	pub byte_len: u16,
}

/// A bounded, canonical envelope with an unverified signer.
#[derive(Clone, Copy, Debug)]
pub struct WorkflowEnvelope<'bytes> {
	/// Exact canonical body candidate.
	pub body: &'bytes [u8],
	/// Untrusted embedded Ed25519 key bytes.
	pub public_key: [u8; 32],
	/// Untrusted signature.
	pub signature: [u8; 64],
}

impl WorkflowEnvelope<'_> {
	/// Builds the exact record signing input. The caller verifies the selected key.
	#[must_use]
	pub fn signing_input(self, kind: WorkflowKind) -> Vec<u8> {
		signing_input(kind, self.body)
	}
}

fn signing_input(kind: WorkflowKind, body: &[u8]) -> Vec<u8> {
	[RECORD_DOMAIN, &(kind as u16).to_le_bytes(), body].concat()
}

/// Canonical signed Unix seconds and a nonnegative nanosecond fraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkflowTimestamp {
	seconds: i64,
	nanoseconds: u32,
}

impl WorkflowTimestamp {
	/// Constructs a time used in workflow headers and native stability facts.
	/// # Errors
	/// Refuses nanoseconds outside the current second.
	pub fn new(seconds: i64, nanoseconds: u32) -> Result<Self, WorkflowError> {
		if nanoseconds >= 1_000_000_000 {
			return Err(WorkflowError::Shape);
		}
		Ok(Self {
			seconds,
			nanoseconds,
		})
	}

	fn write<W: minicbor::encode::Write>(
		self,
		out: &mut minicbor::Encoder<W>,
	) -> Result<(), minicbor::encode::Error<W::Error>> {
		out.array(2)?.i64(self.seconds)?.u32(self.nanoseconds)?;
		Ok(())
	}
}

/// Native device and inode from an authenticated historical endpoint claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeObject {
	/// Kernel device major.
	pub major: u32,
	/// Kernel device minor.
	pub minor: u32,
	/// Kernel inode.
	pub inode: NonZeroU64,
}

/// Checked syntax for the endpoint's Linux location declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxLocation {
	/// Historical boot UUID.
	pub boot: [u8; 16],
	/// Mount namespace device and inode.
	pub mount_namespace: NativeObject,
	/// User namespace device and inode.
	pub user_namespace: NativeObject,
	/// Unique mount ID.
	pub mount: NonZeroU64,
	/// Selected common parent device and inode.
	pub parent: NativeObject,
	/// Selected child root device and inode.
	pub root: NativeObject,
}

/// Exact endpoint selection facts, also used as an untrusted decoded projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointFacts<'name> {
	/// Selected endpoint UUID.
	pub endpoint: [u8; 16],
	/// Selected child root locator UUID.
	pub root: [u8; 16],
	/// Common parent capability locator UUID.
	pub parent: [u8; 16],
	/// Exact basename of the child root.
	pub name: UnixComponent<'name>,
	/// Expected boot, namespace, mount and physical facts.
	pub location: LinuxLocation,
	/// Selected stream byte ceiling. The profile fixes entries, I/O and depth at one.
	pub max_bytes: u64,
}

/// Canonical endpoint syntax. It carries no trusted claims until authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointBody<'name> {
	/// Immutable endpoint record UUIDv7.
	pub id: [u8; 16],
	/// Declared owner profile UUID.
	pub profile: [u8; 16],
	/// Declared owner profile revision.
	pub revision: NonZeroU64,
	/// Recorded endpoint selection.
	pub facts: EndpointFacts<'name>,
}

/// Canonical genesis root syntax. It carries no trusted claims until authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootBody<'name> {
	/// Immutable root UUIDv7.
	pub id: [u8; 16],
	/// Declared owner profile UUID.
	pub profile: [u8; 16],
	/// Declared pair ID.
	pub pair: [u8; 32],
	/// Exact ordered references.
	pub endpoints: [WorkflowRef; 2],
	/// Declared subject filter digest.
	pub filter: [u8; 32],
	/// Declared comparison policy digest.
	pub policy: [u8; 32],
	/// Declared observation scope.
	pub scope: [u8; 32],
	/// Recorded historical scan.
	pub scan: NonZeroU64,
	/// Exact subject basename.
	pub name: UnixComponent<'name>,
	/// Committed paired leaf.
	pub leaf: WorkflowRef,
}

/// Canonical workflow syntax refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkflowError {
	/// An input or declared length exceeds its profile bound.
	Size,
	/// Incorrect, unsupported or malformed field.
	Shape,
	/// An item uses a padded representation or has trailing bytes.
	NonCanonical,
}

impl fmt::Display for WorkflowError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Size => "workflow member exceeds admission bounds",
			Self::Shape => "invalid workflow record shape",
			Self::NonCanonical => "noncanonical workflow record",
		})
	}
}

impl std::error::Error for WorkflowError {}
