//! Independent Ed25519/CBOR/BLAKE3 workflow transcript and bounded refusal cases.

use core::num::NonZeroU64;
use std::io::{self, Read};

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::{MAX_INTERRUPTED_RETRIES, UnixComponent};
use exacopy_plan::workflow_sync::{EndpointFacts, LinuxLocation, NativeObject, WorkflowRef};
use exacopy_transfer::sync_genesis::{
	ExpectedSyncGenesis, SyncGenesisError, SyncGenesisResolver, verify_sync_genesis,
};

#[path = "sync_genesis/manual.rs"]
mod manual;

const VECTORS: &str = include_str!("../verification/sync_genesis/vectors.tsv");

fn hex(value: &str) -> Vec<u8> {
	let (pairs, trailing) = value.as_bytes().as_chunks::<2>();
	assert!(trailing.is_empty());
	pairs
		.iter()
		.map(|chunk| u8::from_str_radix(str::from_utf8(chunk).unwrap(), 16).unwrap())
		.collect()
}

fn digest(value: &str) -> [u8; 32] {
	hex(value).try_into().unwrap()
}

const fn nz(n: u64) -> NonZeroU64 {
	NonZeroU64::new(n).expect("synthetic nonzero identity")
}

const fn object(major: u32, minor: u32, inode: u64) -> NativeObject {
	NativeObject {
		major,
		minor,
		inode: nz(inode),
	}
}

struct ExpectedRoot<'vector> {
	pair: &'vector str,
	filter: &'vector str,
	policy: &'vector str,
	scope: &'vector str,
	roots: [&'vector str; 2],
	leaf: &'vector str,
}

struct Fixture<'vector> {
	case: &'vector str,
	status: &'vector str,
	calls: usize,
	root_digest: [u8; 32],
	root: Vec<u8>,
	members: [Vec<u8>; 3],
	subject: Vec<u8>,
	names: [Vec<u8>; 2],
	max_bytes: u64,
	length: u64,
	projection: ExpectedRoot<'vector>,
}

impl<'vector> Fixture<'vector> {
	fn new(line: &'vector str) -> Self {
		let fields: Vec<_> = line.split('\t').collect();
		let &[
			case,
			status,
			calls,
			root_digest,
			root,
			left,
			right,
			leaf,
			subject,
			left_name,
			right_name,
			max_bytes,
			length,
			pair,
			filter,
			policy,
			scope,
			left_root,
			right_root,
			leaf_digest,
		] = fields.as_slice()
		else {
			panic!("invalid independent fixture {line}");
		};
		Self {
			case,
			status,
			calls: calls.parse().unwrap(),
			root_digest: digest(root_digest),
			root: hex(root),
			members: [hex(left), hex(right), hex(leaf)],
			subject: hex(subject),
			names: [hex(left_name), hex(right_name)],
			max_bytes: max_bytes.parse().unwrap(),
			length: length.parse().unwrap(),
			projection: ExpectedRoot {
				pair,
				filter,
				policy,
				scope,
				roots: [left_root, right_root],
				leaf: leaf_digest,
			},
		}
	}

	fn expected<'selection>(
		&'selection self,
		owner: &'selection VerifyingKey,
	) -> ExpectedSyncGenesis<'selection> {
		let endpoints = [0, 1].map(|index| {
			let side = u8::try_from(index).unwrap();
			EndpointFacts {
				endpoint: [0x21 + side; 16],
				root: [0x31 + side; 16],
				parent: [0x41; 16],
				name: UnixComponent::new(&self.names[index]).unwrap(),
				location: LinuxLocation {
					boot: [0x71; 16],
					mount_namespace: object(0, 4, 23),
					user_namespace: object(0, 4, 24),
					mount: nz(65_536),
					parent: object(8, 1, 70),
					root: object(8, 1, 71 + u64::from(side)),
				},
				max_bytes: self.max_bytes,
			}
		});
		ExpectedSyncGenesis {
			root_digest: self.root_digest,
			profile: [0x44; 16],
			revision: nz(3),
			owner,
			subject: UnixComponent::new(&self.subject).unwrap(),
			endpoints,
			scan: Some(nz(29)),
		}
	}
}

fn owner() -> VerifyingKey {
	SigningKey::from_bytes(&[0x51; 32]).verifying_key()
}

fn first() -> Fixture<'static> {
	Fixture::new(VECTORS.lines().nth(1).unwrap())
}

struct Resolver<'fixture> {
	members: &'fixture [Vec<u8>; 3],
	opened: Vec<WorkflowRef>,
	total: usize,
	missing: Option<usize>,
}

impl<'fixture> Resolver<'fixture> {
	fn new(members: &'fixture [Vec<u8>; 3]) -> Self {
		Self {
			members,
			opened: Vec::new(),
			total: 0,
			missing: None,
		}
	}
}

struct CountedRead<'fixture> {
	bytes: &'fixture [u8],
	total: &'fixture mut usize,
}

impl Read for CountedRead<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		let count = self.bytes.read(output)?;
		*self.total += count;
		Ok(count)
	}
}

impl SyncGenesisResolver for Resolver<'_> {
	type Member<'resolver>
		= CountedRead<'resolver>
	where
		Self: 'resolver;

	fn open(&mut self, reference: WorkflowRef) -> io::Result<Self::Member<'_>> {
		let index = self.opened.len();
		self.opened.push(reference);
		if Some(index) == self.missing {
			return Err(io::ErrorKind::NotFound.into());
		}
		Ok(CountedRead {
			bytes: &self.members[index],
			total: &mut self.total,
		})
	}
}

#[test]
fn independent_signed_workflow_closure_vectors_match_and_refuse() {
	let key = owner();
	for line in VECTORS.lines().skip(1) {
		let fixture = Fixture::new(line);
		let expected = fixture.expected(&key);
		let mut resolver = Resolver::new(&fixture.members);
		let result = verify_sync_genesis(&fixture.root, &expected, &mut resolver);
		assert_eq!(resolver.opened.len(), fixture.calls, "{}", fixture.case);
		let observed = match result {
			Ok(history) => {
				let root = history.root();
				assert_eq!(history.digest(), fixture.root_digest);
				assert_eq!(history.profile_revision(), expected.revision);
				assert_eq!(history.endpoints(), &expected.endpoints);
				assert_eq!(root.pair, digest(fixture.projection.pair));
				assert_eq!(root.filter, digest(fixture.projection.filter));
				assert_eq!(root.policy, digest(fixture.projection.policy));
				assert_eq!(root.scope, digest(fixture.projection.scope));
				assert_eq!(root.leaf.digest, digest(fixture.projection.leaf));
				assert_eq!(
					resolver.opened.as_slice(),
					[root.endpoints[0], root.endpoints[1], root.leaf]
				);
				for (side, identity) in history.sides().iter().zip(fixture.projection.roots) {
					assert_eq!(side.length, fixture.length);
					assert_eq!(side.measured.identity.root, digest(identity));
				}
				"ok"
			}
			Err(SyncGenesisError::Wire(_)) => "wire",
			Err(SyncGenesisError::Selection) => "selection",
			Err(SyncGenesisError::Signature) => "signature",
			Err(SyncGenesisError::Closure) => "closure",
			Err(SyncGenesisError::Read(_)) => "read",
			Err(SyncGenesisError::Leaf(_)) => "leaf",
			Err(error) => panic!("{}: unexpected refusal: {error:?}", fixture.case),
		};
		assert_eq!(observed, fixture.status, "{}", fixture.case);
	}
}

#[test]
fn complete_root_authentication_and_selection_precede_all_child_io() {
	let fixture = first();
	let key = owner();
	let mut expected = fixture.expected(&key);
	let mut resolver = Resolver::new(&fixture.members);
	for cut in 0..fixture.root.len() {
		assert!(verify_sync_genesis(&fixture.root[..cut], &expected, &mut resolver).is_err());
	}
	assert!(verify_sync_genesis(&[0; 2049], &expected, &mut resolver).is_err());
	let mut tampered = fixture.root.clone();
	// The signature precedes the final domain key and code (three bytes).
	let index = tampered.len() - 4;
	tampered[index] ^= 1;
	assert!(matches!(
		verify_sync_genesis(&tampered, &expected, &mut resolver),
		Err(SyncGenesisError::Signature)
	));
	let mut weak_key = [0; 32];
	weak_key[0] = 1;
	let weak = VerifyingKey::from_bytes(&weak_key).unwrap();
	assert!(weak.is_weak());
	assert!(matches!(
		verify_sync_genesis(
			&fixture.root,
			&ExpectedSyncGenesis {
				owner: &weak,
				..expected
			},
			&mut resolver
		),
		Err(SyncGenesisError::Signature)
	));
	expected.endpoints[1].location.root = expected.endpoints[0].location.root;
	assert!(matches!(
		verify_sync_genesis(&fixture.root, &expected, &mut resolver),
		Err(SyncGenesisError::Selection)
	));
	assert!(resolver.opened.is_empty());
	assert_eq!(resolver.total, 0);
}

#[test]
fn refuses_absent_and_overlong_members_without_unbounded_reads() {
	let mut fixture = first();
	let initial_left = fixture.members[0].len();
	let key = owner();
	{
		let expected = fixture.expected(&key);
		let mut missing = Resolver::new(&fixture.members);
		missing.missing = Some(1);
		assert!(matches!(
			verify_sync_genesis(&fixture.root, &expected, &mut missing),
			Err(SyncGenesisError::Read(error)) if error.kind() == io::ErrorKind::NotFound
		));
		assert_eq!(missing.opened.len(), 2);
		assert_eq!(missing.total, initial_left);
	}
	fixture.members[0].extend([0; 4096]);
	let mut large = Resolver::new(&fixture.members);
	assert!(matches!(
		verify_sync_genesis(&fixture.root, &fixture.expected(&key), &mut large),
		Err(SyncGenesisError::Closure)
	));
	assert_eq!(large.opened.len(), 1);
	assert_eq!(large.total, initial_left + 1);
}

#[test]
fn repeated_interrupts_are_bounded() {
	#[derive(Default)]
	struct Interrupted(usize);
	impl Read for &mut Interrupted {
		fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
			self.0 += 1;
			Err(io::ErrorKind::Interrupted.into())
		}
	}
	impl SyncGenesisResolver for Interrupted {
		type Member<'resolver> = &'resolver mut Self;
		fn open(&mut self, _: WorkflowRef) -> io::Result<Self::Member<'_>> {
			Ok(self)
		}
	}
	let fixture = first();
	let key = owner();
	let mut interrupted = Interrupted::default();
	assert!(matches!(
		verify_sync_genesis(&fixture.root, &fixture.expected(&key), &mut interrupted),
		Err(SyncGenesisError::Read(_))
	));
	assert_eq!(interrupted.0, usize::from(MAX_INTERRUPTED_RETRIES) + 1);
}
