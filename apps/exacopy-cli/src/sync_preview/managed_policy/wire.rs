use std::num::{NonZeroU32, NonZeroU64};

use exacopy_plan::workflow_sync::{NativeObject, WorkflowKind, WorkflowRef};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::{
	MANAGED_POLICY_MAX_BYTES, ManagedCooperation, ManagedHistoryMember, ManagedPolicy,
	ManagedPolicyEndpoint, ManagedPolicyError, ManagedPolicyHistory, ManagedPolicyIdentity,
	ManagedPolicyLocation, ManagedPolicyPin,
};

const VERSION: u8 = 1;
const COOPERATION_VERSION: u8 = 1;
const DIGEST_CONTEXT: &str = "ExaCopy local managed sync policy v1";

pub(crate) fn encode(
	identity: &ManagedPolicyIdentity,
	policy: &ManagedPolicy,
) -> Result<(Vec<u8>, ManagedPolicyPin), ManagedPolicyError> {
	identity.validate()?;
	policy.validate(identity.owner_profile)?;
	let mut envelope = Envelope(
		VERSION,
		Hex(identity.selection_id),
		identity.revision,
		Hex([0; 32]),
		Hex(identity.owner_key),
		PolicyRecord::new(identity.owner_profile, policy),
	);
	let digest = envelope.digest()?;
	envelope.3 = Hex(digest);
	let bytes = serde_json::to_vec(&envelope).map_err(|_| ManagedPolicyError::Encoding)?;
	if bytes.len() > MANAGED_POLICY_MAX_BYTES {
		return Err(ManagedPolicyError::Size);
	}
	Ok((
		bytes,
		ManagedPolicyPin {
			identity: *identity,
			digest,
		},
	))
}

pub(crate) fn decode(
	bytes: &[u8],
	expected: &ManagedPolicyPin,
) -> Result<ManagedPolicy, ManagedPolicyError> {
	if bytes.len() > MANAGED_POLICY_MAX_BYTES {
		return Err(ManagedPolicyError::Size);
	}
	expected.identity.validate()?;
	let envelope: Envelope =
		serde_json::from_slice(bytes).map_err(|_| ManagedPolicyError::Encoding)?;
	let canonical = serde_json::to_vec(&envelope).map_err(|_| ManagedPolicyError::Encoding)?;
	let Envelope(version, Hex(selection_id), revision, Hex(digest), Hex(owner_key), record) =
		&envelope;
	if *version != VERSION || canonical != bytes {
		return Err(ManagedPolicyError::Encoding);
	}
	let PolicyRecord(Hex(owner_profile), ..) = record;
	let identity = ManagedPolicyIdentity {
		selection_id: *selection_id,
		revision: *revision,
		owner_profile: *owner_profile,
		owner_key: *owner_key,
	};
	if identity != expected.identity
		|| *digest != expected.digest
		|| envelope.digest()? != expected.digest
	{
		return Err(ManagedPolicyError::Selection);
	}
	let policy = ManagedPolicy::try_from(envelope.5)?;
	policy.validate(identity.owner_profile)?;
	Ok(policy)
}

#[derive(Serialize, Deserialize)]
struct Envelope(
	u8,
	Hex<[u8; 16]>,
	NonZeroU64,
	Hex<[u8; 32]>,
	Hex<[u8; 32]>,
	PolicyRecord,
);

impl Envelope {
	fn digest(&self) -> Result<[u8; 32], ManagedPolicyError> {
		let commitment = (&self.0, &self.1, &self.2, &self.4, &self.5);
		let bytes = serde_json::to_vec(&commitment).map_err(|_| ManagedPolicyError::Encoding)?;
		Ok(blake3::derive_key(DIGEST_CONTEXT, &bytes))
	}
}

#[derive(Serialize, Deserialize)]
struct PolicyRecord(
	Hex<[u8; 16]>,
	(NonZeroU32, NonZeroU32),
	(u8, Hex<[u8; 16]>),
	LiveRecord,
	HistoryRecord,
);

#[derive(Serialize, Deserialize)]
struct LiveRecord(
	Hex<Vec<u8>>,
	Hex<[u8; 16]>,
	LocationRecord,
	Hex<Vec<u8>>,
	[EndpointRecord; 2],
);

#[derive(Serialize, Deserialize)]
struct LocationRecord(
	Hex<[u8; 16]>,
	ObjectRecord,
	ObjectRecord,
	NonZeroU64,
	NonZeroU64,
	ObjectRecord,
);

#[derive(Serialize, Deserialize)]
struct EndpointRecord(
	Hex<[u8; 16]>,
	Hex<[u8; 16]>,
	Hex<Vec<u8>>,
	ObjectRecord,
	u64,
);

#[derive(Serialize, Deserialize)]
struct HistoryRecord(
	Hex<Vec<u8>>,
	ObjectRecord,
	NonZeroU64,
	MemberRecord,
	[MemberRecord; 3],
	Option<NonZeroU64>,
);

#[derive(Serialize, Deserialize)]
struct MemberRecord(Hex<Vec<u8>>, u16, u16, Hex<[u8; 32]>);

#[derive(Serialize, Deserialize)]
struct ObjectRecord(u32, u32, NonZeroU64);

impl PolicyRecord {
	fn new(owner_profile: [u8; 16], policy: &ManagedPolicy) -> Self {
		let location = policy.location;
		let history = &policy.history;
		Self(
			Hex(owner_profile),
			(policy.actor_uid, policy.actor_gid),
			(COOPERATION_VERSION, Hex(policy.cooperation.enrollment_id)),
			LiveRecord(
				Hex(policy.parent_path.clone()),
				Hex(policy.parent_locator),
				LocationRecord(
					Hex(location.boot),
					location.mount_namespace.into(),
					location.user_namespace.into(),
					location.ordinary_mount,
					location.unique_mount,
					location.parent.into(),
				),
				Hex(policy.subject.clone()),
				policy.endpoints.each_ref().map(EndpointRecord::from),
			),
			HistoryRecord(
				Hex(history.path.clone()),
				history.directory.into(),
				history.revision,
				MemberRecord::from(&history.root),
				history.children.each_ref().map(MemberRecord::from),
				history.scan,
			),
		)
	}
}

impl TryFrom<PolicyRecord> for ManagedPolicy {
	type Error = ManagedPolicyError;

	fn try_from(record: PolicyRecord) -> Result<Self, Self::Error> {
		let PolicyRecord(_, (actor_uid, actor_gid), (protocol, Hex(enrollment_id)), live, history) =
			record;
		if protocol != COOPERATION_VERSION {
			return Err(ManagedPolicyError::Scope);
		}
		let LiveRecord(Hex(parent_path), Hex(parent_locator), location, Hex(subject), endpoints) =
			live;
		let LocationRecord(
			Hex(boot),
			mount_namespace,
			user_namespace,
			ordinary_mount,
			unique_mount,
			parent,
		) = location;
		let HistoryRecord(Hex(path), directory, revision, root, [left, right, leaf], scan) =
			history;
		Ok(Self {
			actor_uid,
			actor_gid,
			cooperation: ManagedCooperation { enrollment_id },
			parent_path,
			parent_locator,
			location: ManagedPolicyLocation {
				boot,
				mount_namespace: mount_namespace.into(),
				user_namespace: user_namespace.into(),
				ordinary_mount,
				unique_mount,
				parent: parent.into(),
			},
			subject,
			endpoints: endpoints.map(ManagedPolicyEndpoint::from),
			history: ManagedPolicyHistory {
				path,
				directory: directory.into(),
				revision,
				root: root.try_into()?,
				children: [left.try_into()?, right.try_into()?, leaf.try_into()?],
				scan,
			},
		})
	}
}

impl From<&ManagedPolicyEndpoint> for EndpointRecord {
	fn from(endpoint: &ManagedPolicyEndpoint) -> Self {
		Self(
			Hex(endpoint.endpoint),
			Hex(endpoint.root),
			Hex(endpoint.name.clone()),
			endpoint.object.into(),
			endpoint.max_bytes,
		)
	}
}

impl From<EndpointRecord> for ManagedPolicyEndpoint {
	fn from(
		EndpointRecord(Hex(endpoint), Hex(root), Hex(name), object, max_bytes): EndpointRecord,
	) -> Self {
		Self {
			endpoint,
			root,
			name,
			object: object.into(),
			max_bytes,
		}
	}
}

impl From<&ManagedHistoryMember> for MemberRecord {
	fn from(member: &ManagedHistoryMember) -> Self {
		Self(
			Hex(member.name.clone()),
			member.reference.kind as u16,
			member.reference.byte_len,
			Hex(member.reference.digest),
		)
	}
}

impl TryFrom<MemberRecord> for ManagedHistoryMember {
	type Error = ManagedPolicyError;

	fn try_from(
		MemberRecord(Hex(name), kind, byte_len, Hex(digest)): MemberRecord,
	) -> Result<Self, Self::Error> {
		let kind = match kind {
			1 => WorkflowKind::Endpoint,
			6 => WorkflowKind::Root,
			256 => WorkflowKind::Leaf,
			_ => return Err(ManagedPolicyError::History),
		};
		Ok(Self {
			name,
			reference: WorkflowRef {
				digest,
				kind,
				byte_len,
			},
		})
	}
}

impl From<NativeObject> for ObjectRecord {
	fn from(object: NativeObject) -> Self {
		Self(object.major, object.minor, object.inode)
	}
}

impl From<ObjectRecord> for NativeObject {
	fn from(ObjectRecord(major, minor, inode): ObjectRecord) -> Self {
		Self {
			major,
			minor,
			inode,
		}
	}
}

struct Hex<T>(T);

impl<T: AsRef<[u8]>> Serialize for Hex<T> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		const DIGITS: &[u8; 16] = b"0123456789abcdef";
		let bytes = self.0.as_ref();
		let mut hex = String::with_capacity(bytes.len() * 2);
		for &byte in bytes {
			hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
			hex.push(char::from(DIGITS[usize::from(byte & 0xf)]));
		}
		serializer.serialize_str(&hex)
	}
}

impl<'de, T: TryFrom<Vec<u8>>> Deserialize<'de> for Hex<T> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let hex = String::deserialize(deserializer)?;
		let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
		if !remainder.is_empty() {
			return Err(D::Error::custom("expected even-length lowercase hex"));
		}
		let mut bytes = Vec::with_capacity(pairs.len());
		for &[high, low] in pairs {
			let high = digit(high).ok_or_else(|| D::Error::custom("expected lowercase hex"))?;
			let low = digit(low).ok_or_else(|| D::Error::custom("expected lowercase hex"))?;
			bytes.push((high << 4) | low);
		}
		let value = T::try_from(bytes).map_err(|_| D::Error::custom("incorrect hex length"))?;
		Ok(Self(value))
	}
}

fn digit(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		_ => None,
	}
}
