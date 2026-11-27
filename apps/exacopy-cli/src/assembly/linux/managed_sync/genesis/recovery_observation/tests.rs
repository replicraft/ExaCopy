use std::num::{NonZeroU16, NonZeroU64};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_plan::workflow_sync::{EndpointFacts, LinuxLocation, decode_envelope};
use exacopy_platform::linux::SyncGenesisMemberBinding;

use super::*;

const VECTOR: &str = include_str!(concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/../../crates/engines/exacopy-transfer/verification/sync_genesis/vectors.tsv"
));

#[test]
fn verifies_independently_selected_history_and_refuses_order_or_bytes_substitution() {
	let fields: Vec<_> = VECTOR.lines().nth(1).unwrap().split('\t').collect();
	assert_eq!(fields[0], "valid");
	let [root, left, right, leaf] = [fields[4], fields[5], fields[6], fields[7]].map(hex);
	let [subject, left_name, right_name] = [fields[8], fields[9], fields[10]].map(hex);
	let owner = SigningKey::from_bytes(&[0x51; 32]).verifying_key();
	let history = ExpectedSyncGenesis {
		root_digest: hex(fields[3]).try_into().unwrap(),
		profile: [0x44; 16],
		revision: nz(3),
		owner: &owner,
		subject: UnixComponent::new(&subject).unwrap(),
		endpoints: [
			endpoint(0, &left_name, fields[11].parse().unwrap()),
			endpoint(1, &right_name, fields[11].parse().unwrap()),
		],
		scan: Some(nz(29)),
	};
	let make = |kind: WorkflowKind, bytes: &[u8], canonical_digest| SyncGenesisMemberBinding {
		kind: kind as u16,
		byte_len: NonZeroU16::new(u16::try_from(bytes.len()).unwrap()).unwrap(),
		canonical_digest,
		raw_digest: *blake3::hash(bytes).as_bytes(),
	};
	let device = rustix::fs::makedev(8, 1);
	let output = SyncGenesisNativeIdentity {
		device,
		inode: nz(100),
	};
	let stage = SyncGenesisNativeIdentity {
		device,
		inode: nz(101),
	};
	let intent = SyncGenesisIntent {
		operation: SyncGenesisOperation::new([9; 16]).unwrap(),
		output,
		approval: [3; 32],
		members: [
			make(WorkflowKind::Root, &root, history.root_digest),
			make(WorkflowKind::Endpoint, &left, endpoint_digest(&left)),
			make(WorkflowKind::Endpoint, &right, endpoint_digest(&right)),
			make(
				WorkflowKind::Leaf,
				&leaf,
				hex(fields[19]).try_into().unwrap(),
			),
		],
	};
	let basis = |intent| ManagedGenesisRecoveryBasis {
		intent,
		stage,
		history: &history,
	};
	verify_history([&root, &left, &right, &leaf], basis(&intent)).unwrap();
	assert!(verify_history([&root, &right, &left, &leaf], basis(&intent)).is_err());
	assert!(
		verify_history(
			[&root[..root.len() - 1], &left, &right, &leaf],
			basis(&intent)
		)
		.is_err()
	);

	let mut wrong_raw = intent;
	wrong_raw.members[1].raw_digest[0] ^= 1;
	assert!(verify_history([&root, &left, &right, &leaf], basis(&wrong_raw)).is_err());

	// The closure inventory still contains the original two references. The
	// production reader must refuse their swapped placement in the selected slots.
	let mut reordered = intent;
	reordered.members.swap(1, 2);
	assert!(verify_history([&root, &right, &left, &leaf], basis(&reordered)).is_err());
}

fn endpoint_digest(bytes: &[u8]) -> [u8; 32] {
	let input = decode_envelope(bytes)
		.unwrap()
		.signing_input(WorkflowKind::Endpoint);
	*blake3::hash(&input).as_bytes()
}

fn hex(bytes: &str) -> Vec<u8> {
	let (pairs, remainder) = bytes.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

const fn nz(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).unwrap()
}

const fn object(major: u32, minor: u32, inode: u64) -> NativeObject {
	NativeObject {
		major,
		minor,
		inode: nz(inode),
	}
}

fn endpoint(side: u8, name: &[u8], max_bytes: u64) -> EndpointFacts<'_> {
	EndpointFacts {
		endpoint: [0x21 + side; 16],
		root: [0x31 + side; 16],
		parent: [0x41; 16],
		name: UnixComponent::new(name).unwrap(),
		location: LinuxLocation {
			boot: [0x71; 16],
			mount_namespace: object(0, 4, 23),
			user_namespace: object(0, 4, 24),
			mount: nz(65_536),
			parent: object(8, 1, 70),
			root: object(8, 1, 71 + u64::from(side)),
		},
		max_bytes,
	}
}
