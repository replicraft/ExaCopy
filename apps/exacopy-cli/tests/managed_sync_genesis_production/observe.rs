//! Independent held kernel observations for the producer fixture.

use std::fs::File;
use std::num::NonZeroU32;
use std::path::Path;

use exacopy_cli::assembly::linux::managed_sync::ManagedPolicyLocation;
use exacopy_endpoint::UnixComponent;
use exacopy_plan::workflow_sync::NativeObject;
use exacopy_platform::linux::{
	ManagedSyncExpectedObject, ManagedSyncExpectedRoot, ManagedSyncNativeScope, SyncPreviewError,
	SyncPreviewRoots,
};
use rustix::fs::{OFlags, StatxFlags};
use rustix::process::{getegid, geteuid};

use super::TestResult;
use super::rig::{MOUNT_ID_UNIQUE, kernel_location, mount_id, native_object, object, open_child};

pub(super) struct Anchor {
	pub(super) location: ManagedPolicyLocation,
	pub(super) sides: [NativeObject; 2],
}

pub(super) fn admit(parent: &Path, held: &File) -> TestResult<Anchor> {
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
			println!("\nmanaged_sync_genesis_production=blocked reason={reason}");
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

pub(super) fn expected(observed: NativeObject) -> ManagedSyncExpectedObject {
	ManagedSyncExpectedObject {
		major: observed.major,
		minor: observed.minor,
		inode: observed.inode,
	}
}

pub(super) fn components(names: [&[u8]; 2]) -> [UnixComponent<'_>; 2] {
	names.map(|name| UnixComponent::new(name).unwrap())
}

pub(super) fn observe_scope(
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
