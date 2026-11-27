//! Run explicitly under an ordinary actor on an independently selected whole ext4 root.
//! EXACOPY_MANAGED_SYNC_FIXTURE_PARENT must name an existing owner-private disposable parent.

#![cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]

use std::error::Error;
use std::fs::{File, Metadata};
use std::io;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;

use ed25519_dalek::SigningKey;
use exacopy_cli::assembly::linux::managed_sync::{
	ManagedCooperation, ManagedHistoryMember, ManagedPolicy, ManagedPolicyEndpoint,
	ManagedPolicyHistory, ManagedPolicyLocation, ManagedSyncInit, ManagedSyncPreviewError,
	initialize_managed_preview, preview_managed_history,
};
use exacopy_endpoint::UnixComponent;
use exacopy_model::{SyncCopyTarget, SyncObservation, SyncPathDecision, SyncSide};
use exacopy_plan::workflow_sync::NativeObject;
use exacopy_platform::linux::{
	ManagedSyncError, ManagedSyncExpectedObject, ManagedSyncExpectedRoot, ManagedSyncNativeScope,
	SyncPreviewError, SyncPreviewRoots, SyncProfileStore, SyncProfileStoreError,
};
use exacopy_transfer::linux::sync_preview::{HistoricalPreviewFailure, SyncPreviewFailure};
use rustix::fs::{AtFlags, FlockOperation, OFlags, StatxFlags, flock, statx};
use rustix::process::{getegid, geteuid};

#[path = "managed_sync_production/history.rs"]
mod history;
#[path = "managed_sync_production/rig.rs"]
mod rig;

use rig::{Sandbox, assert_missing, kernel_location, open_child, read};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SEED: [u8; 32] = [0x51; 32]; // Public, fixture-only and never used outside this directory.
const SUBJECT: &[u8] = b"subject-\xff";
const ROOT_NAMES: [&[u8]; 2] = [b"left-\xff", b"right-\xff"];
const ID: [u8; 16] = [0xa1; 16];
const SLOT: &[u8] = b"managed-sync-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1.v1";
const MOUNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);

#[test]
#[ignore = "requires a separately selected owner-private fixture parent on an admitted native ext4 root"]
fn production_managed_init_then_preview_exact_p063_history() -> TestResult {
	let (mut sandbox, anchor) = Sandbox::create(admit)?;
	let result = exercise(&mut sandbox, &anchor.location);
	let live = match (result, sandbox.clean()) {
		(Ok(live), Ok(())) => live,
		(Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
		(Err(exercise), Err(cleanup)) => {
			return Err(io::Error::other(format!(
				"fixture failed ({exercise}); cleanup refused ({cleanup})"
			))
			.into());
		}
	};
	let location = anchor.location;
	println!(
		"\nmanaged_sync_production=passed boot={} mnt_ns={} user_ns={} mount={} unique_mount={} anchor={} anchor_left={} anchor_right={} live={} live_left={} live_right={} controls=7 cleanup=verified",
		uuid::Uuid::from_bytes(location.boot),
		print_object(location.mount_namespace),
		print_object(location.user_namespace),
		location.ordinary_mount,
		location.unique_mount,
		print_object(location.parent),
		print_object(anchor.sides[0]),
		print_object(anchor.sides[1]),
		print_object(live[0]),
		print_object(live[1]),
		print_object(live[2]),
	);
	Ok(())
}

fn exercise(
	sandbox: &mut Sandbox,
	admitted: &ManagedPolicyLocation,
) -> TestResult<[NativeObject; 3]> {
	let sandbox_dir = sandbox.directory.try_clone()?;
	let profile = sandbox.path.join("profile");
	let history_dir = sandbox.path.join("history");
	let live_parent = sandbox.path.join("live");
	let profile_dir = sandbox.mkdir(&sandbox_dir, b"profile")?;
	let history_fd = sandbox.mkdir(&sandbox_dir, b"history")?;
	let live_dir = sandbox.mkdir(&sandbox_dir, b"live")?;
	let [left_root, right_root] = [
		sandbox.mkdir(&live_dir, ROOT_NAMES[0])?,
		sandbox.mkdir(&live_dir, ROOT_NAMES[1])?,
	];
	let live = [&left_root, &right_root];
	let [left_file, right_file] = [
		sandbox.write_new(live[0], SUBJECT, b"abc")?,
		sandbox.write_new(live[1], SUBJECT, b"abc")?,
	];
	sandbox.write_new(&profile_dir, b"owner.seed", &SEED)?;
	let profile_identity = SyncProfileStore::open(&profile)?.identity();
	assert_eq!(
		native_object(profile_identity),
		object(&profile_dir.metadata()?)
	);
	let roots = SyncPreviewRoots::open(&live_parent, components(ROOT_NAMES))?;
	let location = observe_scope(&roots, &live_dir, live, ROOT_NAMES)?;
	assert_eq!(
		(
			location.boot,
			location.mount_namespace,
			location.user_namespace,
			location.ordinary_mount,
			location.unique_mount
		),
		(
			admitted.boot,
			admitted.mount_namespace,
			admitted.user_namespace,
			admitted.ordinary_mount,
			admitted.unique_mount
		),
	);
	let endpoints = [
		ManagedPolicyEndpoint {
			endpoint: [0x21; 16],
			root: [0x31; 16],
			name: ROOT_NAMES[0].to_vec(),
			object: object(&live[0].metadata()?),
			max_bytes: 3,
		},
		ManagedPolicyEndpoint {
			endpoint: [0x22; 16],
			root: [0x32; 16],
			name: ROOT_NAMES[1].to_vec(),
			object: object(&live[1].metadata()?),
			max_bytes: 3,
		},
	];
	let [left, right] = [left_file.metadata()?, right_file.metadata()?];
	let revision = NonZeroU64::new(3).unwrap();
	let scan = NonZeroU64::new(29).unwrap();
	let signer = SigningKey::from_bytes(&SEED);
	let mut profile_id = [0; 16];
	blake3::Hasher::new_derive_key("ExaCopy local CLI profile ID v1")
		.update(signer.verifying_key().as_bytes())
		.finalize_xof()
		.fill(&mut profile_id);
	let genesis = history::Genesis {
		location,
		endpoints: &endpoints,
		parent_locator: [0x41; 16],
		profile: uuid::Builder::from_custom_bytes(profile_id)
			.into_uuid()
			.into_bytes(),
		revision,
		scan,
		subject: SUBJECT,
		mode: 0o600,
		uid: left.uid(),
		gid: left.gid(),
		files: [object(&left), object(&right)],
	};
	for metadata in [&left, &right] {
		assert_eq!(
			(metadata.mode() & 0o7777, metadata.uid(), metadata.gid()),
			(genesis.mode, genesis.uid, genesis.gid)
		);
	}
	let artifacts = history::encode(&genesis, &signer);
	let [root, left_history, right_history, leaf] =
		std::array::from_fn(|index| ManagedHistoryMember {
			name: history::NAMES[index].as_bytes().to_vec(),
			reference: artifacts[index].reference,
		});
	for (name, artifact) in history::NAMES.into_iter().zip(&artifacts) {
		sandbox.write_new(&history_fd, name.as_bytes(), &artifact.bytes)?;
	}
	let mut policy = ManagedPolicy {
		actor_uid: NonZeroU32::new(geteuid().as_raw()).ok_or("ordinary uid required")?,
		actor_gid: NonZeroU32::new(getegid().as_raw()).ok_or("ordinary gid required")?,
		cooperation: ManagedCooperation {
			enrollment_id: [0x42; 16],
		},
		parent_path: live_parent.as_os_str().as_bytes().to_vec(),
		parent_locator: [0x41; 16],
		location,
		subject: SUBJECT.to_vec(),
		endpoints,
		history: ManagedPolicyHistory {
			path: history_dir.as_os_str().as_bytes().to_vec(),
			directory: object(&history_fd.metadata()?),
			revision,
			root,
			children: [left_history, right_history, leaf],
			scan: Some(scan),
		},
	};

	assert_missing(&profile_dir, SLOT);
	let approved = policy.endpoints[1].object.inode;
	// A held regular file cannot share the live or historical directory inode.
	policy.endpoints[1].object.inode = object(&right).inode;
	let refusal = initialize_managed_preview(request(&profile, profile_identity, &policy)).err();
	assert!(
		matches!(
			refusal,
			Some(ManagedSyncPreviewError::Managed(
				ManagedSyncError::ScopeMismatch
			))
		),
		"wrong selected right root must refuse before policy creation, observed {refusal:?}"
	);
	policy.endpoints[1].object.inode = approved;
	assert_missing(&profile_dir, SLOT);

	// The writer must exclude Init before it can create the selected slot.
	let writer = open_child(&sandbox_dir, b"live", OFlags::RDONLY | OFlags::DIRECTORY)?;
	flock(&writer, FlockOperation::NonBlockingLockExclusive)?;
	let refusal = initialize_managed_preview(request(&profile, profile_identity, &policy)).err();
	assert!(
		matches!(
			&refusal,
			Some(ManagedSyncPreviewError::Managed(ManagedSyncError::Busy))
		),
		"Init under a competing parent lease must be busy, observed {refusal:?}"
	);
	assert_missing(&profile_dir, SLOT);
	drop(writer);

	let selection = initialize_managed_preview(request(&profile, profile_identity, &policy))?;
	sandbox.track_created_slot(&profile_dir, SLOT)?;
	assert_eq!(selection.profile_identity(), profile_identity);
	assert_eq!(selection.selection_id(), ID);
	assert_eq!(selection.selection_revision(), NonZeroU64::new(7).unwrap());
	assert_eq!(selection.owner_key(), signer.verifying_key().to_bytes());
	let sealed = read(&profile_dir, SLOT)?;
	let sealed_metadata = open_child(&profile_dir, SLOT, OFlags::RDONLY)?.metadata()?;
	assert_eq!(
		(sealed_metadata.mode() & 0o7777, sealed_metadata.nlink()),
		(0o600, 1)
	);
	assert!(!sealed.is_empty());
	let refusal = initialize_managed_preview(request(&profile, profile_identity, &policy)).err();
	assert!(
		matches!(
			&refusal,
			Some(ManagedSyncPreviewError::Store(
				SyncProfileStoreError::AlreadyExists
			))
		),
		"repeated Init must refuse the incumbent slot, observed {refusal:?}"
	);
	assert_eq!(read(&profile_dir, SLOT)?, sealed);

	// Remove the disposable seed from its selected name to prove preview needs only custody and the receipt.
	sandbox.rename(&profile_dir, b"owner.seed", b"retained-fixture-seed")?;
	assert_missing(&profile_dir, b"owner.seed");
	let writer = open_child(&sandbox_dir, b"live", OFlags::RDONLY | OFlags::DIRECTORY)?;
	flock(&writer, FlockOperation::NonBlockingLockExclusive)?;
	right_file.write_all_at(b"xyz", 0)?;
	let refusal = preview_managed_history(&selection, &mut [0; 16]).err();
	assert!(
		matches!(
			&refusal,
			Some(ManagedSyncPreviewError::Managed(ManagedSyncError::Busy))
		),
		"preview under a competing parent lease must be busy, observed {refusal:?}"
	);
	drop(writer);
	let report = preview_managed_history(&selection, &mut [0; 16])?;
	assert_eq!(
		report.decision,
		SyncPathDecision::CopyCandidate {
			from: SyncSide::Right,
			target: SyncCopyTarget::ExistingIncumbent
		}
	);
	for (observation, content) in report.observations.into_iter().zip([b"abc", b"xyz"]) {
		let SyncObservation::Present(evidence) = observation else {
			panic!("expected two independently measured files");
		};
		assert_eq!(evidence.byte_len, 3);
		assert_eq!(evidence.content_digest, *blake3::hash(content).as_bytes());
	}
	assert_live(live, [b"abc", b"xyz"])?;

	let writer = open_child(&sandbox_dir, b"live", OFlags::RDONLY | OFlags::DIRECTORY)?;
	flock(&writer, FlockOperation::NonBlockingLockExclusive)?;
	right_file.write_all_at(b"xyzz", 0)?;
	drop(writer);
	let refusal = preview_managed_history(&selection, &mut [0; 16]).err();
	assert!(
		matches!(&refusal, Some(ManagedSyncPreviewError::Preview(error))
			if matches!(**error, HistoricalPreviewFailure::Live(SyncPreviewFailure::FileLimit(SyncSide::Right)))),
		"over-ceiling right subject must refuse at its byte limit, observed {refusal:?}"
	);
	assert_live(live, [b"abc", b"xyzz"])?;

	// Selected history is mandatory. No alternate first-run preview could pass this typed refusal.
	let history_root = history::NAMES[0].as_bytes();
	let retained = b"retained-fixture-root";
	sandbox.rename(&history_fd, history_root, retained)?;
	let refusal = preview_managed_history(&selection, &mut [0; 16]).err();
	assert!(
		matches!(&refusal, Some(ManagedSyncPreviewError::ReadHistory(error)) if error.kind() == io::ErrorKind::NotFound),
		"missing selected history must refuse before preview, observed {refusal:?}"
	);
	sandbox.rename(&history_fd, retained, history_root)?;
	assert_eq!(read(&profile_dir, SLOT)?, sealed);
	assert_eq!(
		open_child(&profile_dir, SLOT, OFlags::RDONLY)?
			.metadata()?
			.ino(),
		sealed_metadata.ino()
	);
	assert_eq!(read(&profile_dir, b"retained-fixture-seed")?, SEED);
	for (name, artifact) in history::NAMES.into_iter().zip(artifacts) {
		assert_eq!(read(&history_fd, name.as_bytes())?, artifact.bytes);
	}
	assert_live(live, [b"abc", b"xyzz"])?;
	Ok([
		location.parent,
		policy.endpoints[0].object,
		policy.endpoints[1].object,
	])
}

fn request<'a>(
	profile: &'a Path,
	profile_identity: exacopy_platform::linux::FileIdentity,
	policy: &'a ManagedPolicy,
) -> ManagedSyncInit<'a> {
	ManagedSyncInit {
		profile,
		profile_identity,
		selection_id: ID,
		selection_revision: NonZeroU64::new(7).unwrap(),
		policy,
	}
}

struct Anchor {
	location: ManagedPolicyLocation,
	sides: [NativeObject; 2],
}

fn admit(parent: &Path, held: &File) -> TestResult<Anchor> {
	let names: [&[u8]; 2] = [b"left", b"right"];
	let native_names = components(names);
	let roots = SyncPreviewRoots::open(parent, native_names)?;
	let [left, right] = [
		open_child(held, names[0], OFlags::RDONLY | OFlags::DIRECTORY)?,
		open_child(held, names[1], OFlags::RDONLY | OFlags::DIRECTORY)?,
	];

	let current = roots.selection();
	assert_eq!(native_object(current.parent), object(&held.metadata()?));
	assert_eq!(
		current.roots.map(native_object),
		[object(&left.metadata()?), object(&right.metadata()?)],
	);
	if let Err(error) = roots.require_unmapped_history_mount() {
		let reason = match &error {
			SyncPreviewError::UnsupportedHistoryMountAttributes => {
				Some("statmount-attributes-unavailable")
			}
			SyncPreviewError::IdMappedHistoryMount => Some("idmapped-history-mount"),
			_ => None,
		};
		if let Some(reason) = reason {
			println!("\nmanaged_sync_production=blocked reason={reason}");
		}
		return Err(error.into());
	}
	let location = observe_scope(&roots, held, [&left, &right], names)?;
	let sides = [object(&left.metadata()?), object(&right.metadata()?)];
	let scope = ManagedSyncNativeScope {
		parent_path: parent,
		uid: NonZeroU32::new(geteuid().as_raw()).ok_or("ordinary uid required")?,
		gid: NonZeroU32::new(getegid().as_raw()).ok_or("ordinary gid required")?,
		subject: UnixComponent::new(b"statmount-probe").unwrap(),
		boot: location.boot,
		mount_namespace: expected(location.mount_namespace),
		user_namespace: expected(location.user_namespace),
		ordinary_mount: location.ordinary_mount,
		unique_mount: location.unique_mount,
		parent: expected(location.parent),
		roots: [
			ManagedSyncExpectedRoot {
				name: native_names[0],
				identity: expected(sides[0]),
			},
			ManagedSyncExpectedRoot {
				name: native_names[1],
				identity: expected(sides[1]),
			},
		],
	};
	let lease = roots.acquire_managed_history_lease(scope)?;
	lease.recheck_roots()?;
	Ok(Anchor { location, sides })
}

fn expected(observed: NativeObject) -> ManagedSyncExpectedObject {
	ManagedSyncExpectedObject {
		major: observed.major,
		minor: observed.minor,
		inode: observed.inode,
	}
}

fn components(names: [&[u8]; 2]) -> [UnixComponent<'_>; 2] {
	names.map(|name| UnixComponent::new(name).unwrap())
}

fn observe_scope(
	roots: &SyncPreviewRoots<'_>,
	directory: &File,
	held_roots: [&File; 2],
	names: [&[u8]; 2],
) -> TestResult<ManagedPolicyLocation> {
	let facts = roots.recheck_history_roots()?;
	let selection = roots.selection();
	let ordinary = mount_id(directory, StatxFlags::MNT_ID)?;
	let unique = mount_id(directory, MOUNT_ID_UNIQUE)?;
	assert_eq!(selection.mount_id, ordinary.get());
	let (boot, mount_namespace, user_namespace) = kernel_location()?;
	let parent = object(&directory.metadata()?);
	for (index, fact) in facts.into_iter().enumerate() {
		assert_eq!(fact.boot, boot);
		assert_eq!(native_object(fact.mount_namespace), mount_namespace);
		assert_eq!(native_object(fact.user_namespace), user_namespace);
		assert_eq!(fact.unique_mount, unique);
		assert_eq!(native_object(fact.parent), parent);
		assert_eq!(
			native_object(fact.root),
			object(&held_roots[index].metadata()?)
		);
		assert_eq!(fact.root_name, UnixComponent::new(names[index]).unwrap());
	}
	Ok(ManagedPolicyLocation {
		boot,
		mount_namespace,
		user_namespace,
		ordinary_mount: ordinary,
		unique_mount: unique,
		parent,
	})
}

fn print_object(native: NativeObject) -> String {
	format!("{}:{}:{}", native.major, native.minor, native.inode)
}

fn mount_id(directory: &File, flag: StatxFlags) -> TestResult<NonZeroU64> {
	let stat = statx(directory, c"", AtFlags::EMPTY_PATH, flag)?;
	assert_ne!(stat.stx_mask & flag.bits(), 0);
	NonZeroU64::new(stat.stx_mnt_id).ok_or_else(|| "kernel omitted requested mount ID".into())
}

fn native_object(identity: exacopy_platform::linux::FileIdentity) -> NativeObject {
	device_inode(identity.device(), identity.inode())
}

fn object(metadata: &Metadata) -> NativeObject {
	device_inode(metadata.dev(), metadata.ino())
}

fn device_inode(device: u64, inode: u64) -> NativeObject {
	NativeObject {
		major: rustix::fs::major(device),
		minor: rustix::fs::minor(device),
		inode: NonZeroU64::new(inode).unwrap(),
	}
}

fn assert_live(roots: [&File; 2], contents: [&[u8]; 2]) -> TestResult {
	for (root, expected) in roots.into_iter().zip(contents) {
		assert_eq!(read(root, SUBJECT)?, expected);
		assert_eq!(
			open_child(root, SUBJECT, OFlags::RDONLY)?
				.metadata()?
				.mode()
				& 0o7777,
			0o600
		);
	}
	Ok(())
}
