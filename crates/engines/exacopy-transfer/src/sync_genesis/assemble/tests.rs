use exacopy_manifest::sync_baseline::{Identity, LinuxOwnerMode, Observation};
use exacopy_plan::workflow_sync::{LinuxLocation, NativeObject, native_id};

use super::*;

const VECTORS: &str = include_str!("../../../verification/sync_genesis/vectors.tsv");
const BOOT: [u8; 16] = [0x71; 16];

const fn nz(number: u64) -> NonZeroU64 {
	NonZeroU64::new(number).expect("nonzero fixture value")
}

const fn native(major: u32, minor: u32, inode: u64) -> NativeObject {
	NativeObject {
		major,
		minor,
		inode: nz(inode),
	}
}

fn id(value: u8) -> [u8; 16] {
	let mut bytes = [value; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

fn hex(value: &str) -> Vec<u8> {
	let (pairs, tail) = value.as_bytes().as_chunks::<2>();
	assert!(tail.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn selected(owner: &VerifyingKey, limit: u64) -> SyncGenesisSelection<'_> {
	let endpoints = [(0u8, b"A\xff"), (1, b"B\xff")].map(|(side, name)| EndpointFacts {
		endpoint: [0x21 + side; 16],
		root: [0x31 + side; 16],
		parent: [0x41; 16],
		name: UnixComponent::new(name).unwrap(),
		location: LinuxLocation {
			boot: BOOT,
			mount_namespace: native(0, 4, 23),
			user_namespace: native(0, 4, 24),
			mount: nz(65_536),
			parent: native(8, 1, 70),
			root: native(8, 1, 71 + u64::from(side)),
		},
		max_bytes: limit,
	});
	SyncGenesisSelection {
		profile: [0x44; 16],
		revision: nz(3),
		owner,
		subject: UnixComponent::new(b"subject-\xff").unwrap(),
		endpoints,
		scan: nz(29),
	}
}

fn records() -> SyncGenesisRecords {
	SyncGenesisRecords {
		root: id(0x83),
		endpoints: [id(0x81), id(0x82)],
		created_at: WorkflowTimestamp::new(12, 19).unwrap(),
	}
}

fn measured() -> [SideEvidence; 2] {
	[0u8, 1].map(|side| {
		let index = u64::from(side);
		let metadata = LinuxOwnerMode {
			mode: 0o754,
			uid: u32::MAX,
			gid: 1024,
		};
		let measured = Observation {
			identity: Identity {
				root: native_id(BOOT, native(8, 1, 71 + index)),
				file: native_id(BOOT, native(8, 1, 80 + index)),
			},
			position: nz(1 + index),
			stability: [0x30 + side; 32],
		};
		SideEvidence {
			measured,
			rechecked: Observation {
				position: nz(3 + index),
				..measured
			},
			length: 3,
			stream_digest: *blake3::hash(b"abc").as_bytes(),
			metadata,
			metadata_digest: metadata.digest().unwrap(),
		}
	})
}

#[test]
fn assembly_matches_independent_canonical_signed_closure() {
	let signer = SigningKey::from_bytes(&[0x51; 32]);
	let (key, sides) = (signer.verifying_key(), measured());
	let vector: Vec<_> = VECTORS.lines().nth(1).unwrap().split('\t').collect();
	assert_eq!(vector[0], "valid");
	let selection = selected(&key, vector[11].parse().unwrap());
	let closure = assemble_sync_genesis(selection, records(), sides, &signer).unwrap();
	assert_eq!(&closure.root_digest()[..], hex(vector[3]));
	assert_eq!(closure.root_bytes(), hex(vector[4]));
	let members = closure.members();
	assert_eq!(
		members.map(|(_, reference)| reference.kind),
		[
			WorkflowKind::Endpoint,
			WorkflowKind::Endpoint,
			WorkflowKind::Leaf
		],
	);
	for ((actual, reference), expected) in members.into_iter().zip(&vector[5..8]) {
		assert_eq!(actual, hex(expected));
		assert_eq!(usize::from(reference.byte_len), actual.len());
	}
}

#[test]
fn assembly_returns_no_closure_for_foreign_signer_or_duplicate_records() {
	let signer = SigningKey::from_bytes(&[0x51; 32]);
	let other = SigningKey::from_bytes(&[0x67; 32]);
	let key = signer.verifying_key();
	let selection = selected(&key, 3);
	let mut ids = records();
	assert!(matches!(
		assemble_sync_genesis(selection, ids, measured(), &other),
		Err(Error::Signature)
	));
	ids.endpoints[1] = ids.root;
	assert!(matches!(
		assemble_sync_genesis(selection, ids, measured(), &signer),
		Err(Error::Closure)
	));
}

#[test]
fn assembly_verifies_measured_order_live_side_bounds_and_root_aliases() {
	let signer = SigningKey::from_bytes(&[0x51; 32]);
	let key = signer.verifying_key();
	let sides = measured();
	assert!(matches!(
		assemble_sync_genesis(selected(&key, 3), records(), [sides[1], sides[0]], &signer),
		Err(Error::Leaf(_))
	));
	assert!(matches!(
		assemble_sync_genesis(selected(&key, 2), records(), sides, &signer),
		Err(Error::Closure)
	));

	let selection = selected(&key, 3);
	let mut aliased = sides;
	let parent = native_id(BOOT, selection.endpoints[0].location.parent);
	aliased[0].measured.identity.file = parent;
	aliased[0].rechecked.identity.file = parent;
	assert!(matches!(
		assemble_sync_genesis(selection, records(), aliased, &signer),
		Err(Error::Closure)
	));
}
