//! Test-only P063 genesis encoder derived from the independent Python oracle.
//! The production record parser, digest helpers and signer assembly are absent.

use std::num::NonZeroU64;

use ed25519_dalek::{Signer as _, SigningKey};
use exacopy_cli::assembly::linux::managed_sync::{ManagedPolicyEndpoint, ManagedPolicyLocation};
use exacopy_plan::workflow_sync::{NativeObject, WorkflowKind, WorkflowRef};

use Value::{Array, Bytes, Map, Null, Text, Unsigned};

pub(super) const NAMES: [&str; 4] = ["genesis.cbor", "left.cbor", "right.cbor", "leaf.cbor"];
const RECORD: &[u8] = b"ExaCopy/workflow-record/v1\0";
const PAGE: &[u8] = b"ExaCopy/workflow-page/v1\0";

pub(super) struct Artifact {
	pub(super) reference: WorkflowRef,
	pub(super) bytes: Vec<u8>,
}

pub(super) struct Genesis<'a> {
	pub(super) location: ManagedPolicyLocation,
	pub(super) endpoints: &'a [ManagedPolicyEndpoint; 2],
	pub(super) parent_locator: [u8; 16],
	pub(super) profile: [u8; 16],
	pub(super) revision: NonZeroU64,
	pub(super) scan: NonZeroU64,
	pub(super) subject: &'a [u8],
	pub(super) mode: u32,
	pub(super) uid: u32,
	pub(super) gid: u32,
	pub(super) files: [NativeObject; 2],
}

pub(super) fn encode(genesis: &Genesis<'_>, signer: &SigningKey) -> [Artifact; 4] {
	let location = |root| {
		Array(vec![
			bytes(genesis.location.boot),
			object(genesis.location.mount_namespace),
			object(genesis.location.user_namespace),
			u(genesis.location.unique_mount.get()),
			object(genesis.location.parent),
			object(root),
		])
	};
	let [left, right] = genesis.endpoints.each_ref().map(|ep| location(ep.object));
	let roots = genesis
		.endpoints
		.each_ref()
		.map(|ep| object_digest(genesis.location.boot, ep.object));
	let endpoints = std::array::from_fn::<_, 2, _>(|index| {
		let ep = &genesis.endpoints[index];
		let loc = [&left, &right][index];
		let record = Map(vec![
			bytes(ep.endpoint),
			u(0_u8),
			u(genesis.revision.get()),
			Null,
			bytes(digest(b"local-only/v1", &Null)),
			bytes(ep.root),
			Bytes(loc.encode()),
			Text("linux-managed-local-sync-genesis-v1"),
			Map(vec![
				u(0_u8),
				u(0_u8),
				u(0_u8),
				u(0_u8),
				u(0_u8),
				u(3_u8),
				u(2_u8),
				Null,
			]),
			Map(vec![
				bytes(genesis.parent_locator),
				Array(vec![component(&ep.name)]),
			]),
			Map(vec![u(ep.max_bytes), u(1_u8), u(1_u8), u(1_u8)]),
			Null,
		]);
		signed(
			WorkflowKind::Endpoint,
			header(1, [0x81, 0x82][index], genesis.profile, 1, record),
			signer,
		)
	});
	let filter = digest(b"filter/v1", &Array(vec![component(genesis.subject)]));
	let conflict = digest(b"policy/v1", &Array(vec![u(0_u8); 4]));
	let pair = digest(
		b"pair/v1",
		&Array(vec![
			bytes(genesis.profile),
			u(genesis.revision.get()),
			endpoint_id(genesis, 0),
			endpoint_id(genesis, 1),
			bytes(filter),
			bytes(conflict),
		]),
	);
	let scope = digest(
		b"scope/v1",
		&Array(vec![
			bytes(pair),
			bytes(signer.verifying_key().to_bytes()),
			bytes(endpoints[0].reference.digest),
			bytes(endpoints[1].reference.digest),
			bytes(roots[0]),
			bytes(roots[1]),
			left,
			right,
		]),
	);
	let sides = std::array::from_fn::<_, 2, _>(|index| {
		let file = object_digest(genesis.location.boot, genesis.files[index]);
		let vnode = Array(vec![bytes(roots[index]), bytes(file)]);
		let metadata = Array(vec![u(genesis.mode), u(genesis.uid), u(genesis.gid)]);
		let position = [1_u8, 2][index];
		// P063 records opaque historical observation marks. The held identity is real.
		let mark = bytes([[0x30; 32], [0x31; 32]][index]);
		Map(vec![
			u(2_u8),
			vnode.clone(),
			u(3_u8),
			bytes(digest(b"linux-owner-mode/v1", &metadata)),
			bytes(*blake3::hash(b"abc").as_bytes()),
			Map(vec![
				u(position),
				mark.clone(),
				u(position + 2),
				vnode,
				mark,
				u(0_u8),
			]),
			Array(vec![]),
			metadata,
		])
	});
	let [left, right] = sides;
	let leaf = Map(vec![
		Array(vec![u(1_u8), u(0_u8)]),
		u(256_u16),
		u(0_u8),
		Array(vec![Map(vec![
			Array(vec![component(genesis.subject)]),
			left,
			right,
			u(0_u8),
			Null,
			Map(vec![bytes(scope), bytes(conflict), u(genesis.scan.get())]),
		])]),
		Array(vec![]),
		u(1_u8),
	])
	.encode();
	let leaf = artifact(
		WorkflowKind::Leaf,
		hash(&[
			PAGE,
			&256_u16.to_le_bytes(),
			&u64::try_from(leaf.len()).unwrap().to_le_bytes(),
			&leaf,
		]),
		leaf,
	);
	let [left, right] = endpoints;
	let root_body = Map(vec![
		bytes(pair),
		u(1_u8),
		Null,
		Array(vec![reference(&left), reference(&right)]),
		Map(vec![bytes(filter), bytes(conflict)]),
		Map(vec![
			u(0_u8),
			u(0_u8),
			bytes(scope),
			u(genesis.scan.get()),
			component(genesis.subject),
		]),
		Array(vec![reference(&leaf)]),
		u(1_u8),
		Array(vec![]),
		Array(vec![]),
	]);
	let root = signed(
		WorkflowKind::Root,
		header(6, 0x83, genesis.profile, 69, root_body),
		signer,
	);
	[root, left, right, leaf]
}

fn endpoint_id(genesis: &Genesis<'_>, index: usize) -> Value {
	let ep = &genesis.endpoints[index];
	Array(vec![bytes(ep.endpoint), bytes(ep.root)])
}

fn component(name: &[u8]) -> Value {
	Map(vec![u(1_u8), Bytes(name.to_vec())])
}

fn header(kind: u16, label: u8, profile: [u8; 16], features: u8, body: Value) -> Value {
	let mut id = [label; 16];
	id[6] = 0x70;
	id[8] = 0x80;
	Map(vec![
		Map(vec![u(1_u8), u(0_u8), u(features)]),
		u(kind),
		bytes(id),
		bytes(profile),
		Null,
		body,
		Array(vec![u(12_u8), u(19_u8)]),
		u(1_u8),
	])
}

fn signed(kind: WorkflowKind, body: Value, signer: &SigningKey) -> Artifact {
	let body = body.encode();
	let kind_bytes = (kind as u16).to_le_bytes();
	let message = [RECORD, &kind_bytes, body.as_slice()].concat();
	let signature = signer.sign(&message);
	let envelope = Map(vec![
		Bytes(body),
		bytes(signer.verifying_key().to_bytes()),
		bytes(signature.to_bytes()),
		u(32_u8),
	]);
	artifact(kind, *blake3::hash(&message).as_bytes(), envelope.encode())
}

fn artifact(kind: WorkflowKind, digest: [u8; 32], bytes: Vec<u8>) -> Artifact {
	Artifact {
		reference: WorkflowRef {
			digest,
			kind,
			byte_len: u16::try_from(bytes.len()).unwrap(),
		},
		bytes,
	}
}

fn reference(artifact: &Artifact) -> Value {
	let reference = artifact.reference;
	Map(vec![
		bytes(reference.digest),
		u(reference.kind as u16),
		u(reference.byte_len),
		u(1_u8),
	])
}

fn object(native: NativeObject) -> Value {
	Array(vec![
		Array(vec![u(native.major), u(native.minor)]),
		u(native.inode.get()),
	])
}

fn object_digest(boot: [u8; 16], native: NativeObject) -> [u8; 32] {
	let Array(device_inode) = object(native) else {
		unreachable!()
	};
	let mut terms = vec![bytes(boot)];
	terms.extend(device_inode);
	digest(b"linux-object/v1", &Array(terms))
}

fn digest(suffix: &[u8], value: &Value) -> [u8; 32] {
	hash(&[b"ExaCopy/sync-baseline/", suffix, b"\0", &value.encode()])
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
	let mut hash = blake3::Hasher::new();
	for part in parts {
		hash.update(part);
	}
	*hash.finalize().as_bytes()
}

fn bytes<const N: usize>(bytes: [u8; N]) -> Value {
	Bytes(bytes.to_vec())
}

fn u(value: impl Into<u64>) -> Value {
	Unsigned(value.into())
}

#[derive(Clone)]
enum Value {
	Unsigned(u64),
	Bytes(Vec<u8>),
	Text(&'static str),
	Array(Vec<Self>),
	Map(Vec<Self>),
	Null,
}

impl Value {
	fn encode(&self) -> Vec<u8> {
		let mut output = Vec::new();
		self.write(&mut output);
		output
	}

	fn write(&self, output: &mut Vec<u8>) {
		match self {
			Unsigned(value) => prefix(output, 0, *value),
			Bytes(value) => {
				prefix(output, 2, value.len().try_into().unwrap());
				output.extend(value);
			}
			Text(value) => {
				prefix(output, 3, value.len().try_into().unwrap());
				output.extend(value.as_bytes());
			}
			Array(values) => {
				prefix(output, 4, values.len().try_into().unwrap());
				for value in values {
					value.write(output);
				}
			}
			Map(values) => {
				prefix(output, 5, values.len().try_into().unwrap());
				for (key, value) in values.iter().enumerate() {
					prefix(output, 0, key.try_into().unwrap());
					value.write(output);
				}
			}
			Null => output.push(0xf6),
		}
	}
}

fn prefix(output: &mut Vec<u8>, major: u8, value: u64) {
	let base = major << 5;
	if value < 24 {
		output.push(base | u8::try_from(value).unwrap());
	} else if let Ok(value) = u8::try_from(value) {
		output.extend([base | 24, value]);
	} else if let Ok(value) = u16::try_from(value) {
		output.push(base | 25);
		output.extend(value.to_be_bytes());
	} else if let Ok(value) = u32::try_from(value) {
		output.push(base | 26);
		output.extend(value.to_be_bytes());
	} else {
		output.push(base | 27);
		output.extend(value.to_be_bytes());
	}
}
