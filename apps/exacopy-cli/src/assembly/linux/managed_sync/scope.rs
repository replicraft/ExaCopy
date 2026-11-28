use std::num::NonZeroU64;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use exacopy_plan::workflow_sync::{EndpointFacts, LinuxLocation, NativeObject};
use exacopy_platform::linux::{
	FileIdentity, ManagedSyncExpectedObject, ManagedSyncExpectedRoot, ManagedSyncNativeScope,
	SyncHistoryLocation,
};
use rustix::fs;

use crate::sync_preview::managed_policy::ManagedPolicy;

use super::ManagedSyncPreviewError;

pub(super) fn expected_native(
	policy: &ManagedPolicy,
) -> Result<ManagedSyncNativeScope<'_>, ManagedSyncPreviewError> {
	let location = &policy.location;
	let roots = &policy.endpoints;
	Ok(ManagedSyncNativeScope {
		parent_path: raw_path(&policy.parent_path),
		uid: policy.actor_uid,
		gid: policy.actor_gid,
		subject: component(&policy.subject)?,
		boot: location.boot,
		mount_namespace: expected_object(location.mount_namespace),
		user_namespace: expected_object(location.user_namespace),
		ordinary_mount: location.ordinary_mount,
		unique_mount: location.unique_mount,
		parent: expected_object(location.parent),
		roots: [
			ManagedSyncExpectedRoot {
				name: component(&roots[0].name)?,
				identity: expected_object(roots[0].object),
			},
			ManagedSyncExpectedRoot {
				name: component(&roots[1].name)?,
				identity: expected_object(roots[1].object),
			},
		],
	})
}

pub(super) fn fresh_endpoints<'view>(
	policy: &'view ManagedPolicy,
	actual: [SyncHistoryLocation<'view>; 2],
) -> Result<[EndpointFacts<'view>; 2], ManagedSyncPreviewError> {
	let [left, right] = policy
		.endpoint_facts()
		.map_err(ManagedSyncPreviewError::Policy)?;
	let [left_actual, right_actual] = actual;
	Ok([
		fresh_endpoint(left, left_actual)?,
		fresh_endpoint(right, right_actual)?,
	])
}

pub(super) fn fresh_endpoint<'view>(
	selected: EndpointFacts<'view>,
	actual: SyncHistoryLocation<'view>,
) -> Result<EndpointFacts<'view>, ManagedSyncPreviewError> {
	let live = EndpointFacts {
		name: actual.root_name,
		location: LinuxLocation {
			boot: actual.boot,
			mount_namespace: native_object(actual.mount_namespace)?,
			user_namespace: native_object(actual.user_namespace)?,
			mount: actual.unique_mount,
			parent: native_object(actual.parent)?,
			root: native_object(actual.root)?,
		},
		..selected
	};
	if live != selected {
		return Err(ManagedSyncPreviewError::Selection);
	}
	Ok(live)
}

pub(super) fn raw_path(bytes: &[u8]) -> &Path {
	Path::new(std::ffi::OsStr::from_bytes(bytes))
}

pub(super) fn component(bytes: &[u8]) -> Result<UnixComponent<'_>, ManagedSyncPreviewError> {
	UnixComponent::new(bytes).map_err(|_| ManagedSyncPreviewError::Selection)
}

pub(super) fn native_object(held: FileIdentity) -> Result<NativeObject, ManagedSyncPreviewError> {
	Ok(NativeObject {
		major: fs::major(held.device()),
		minor: fs::minor(held.device()),
		inode: NonZeroU64::new(held.inode()).ok_or(ManagedSyncPreviewError::Selection)?,
	})
}

pub(super) const fn expected_object(value: NativeObject) -> ManagedSyncExpectedObject {
	ManagedSyncExpectedObject {
		major: value.major,
		minor: value.minor,
		inode: value.inode,
	}
}
