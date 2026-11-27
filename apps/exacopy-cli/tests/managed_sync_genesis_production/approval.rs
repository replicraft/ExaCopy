//! Independent fixed-order genesis enrollment and approval projections.

use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_cli::assembly::linux::managed_sync::genesis::ManagedGenesisRequest;
use exacopy_platform::linux::ManagedSyncExpectedObject;

fn append_object(out: &mut Vec<u8>, object: ManagedSyncExpectedObject) {
	out.extend(object.major.to_le_bytes());
	out.extend(object.minor.to_le_bytes());
	out.extend(object.inode.get().to_le_bytes());
}

fn framed_hash(domain: &[u8], role: u8, value: &[u8]) -> [u8; 32] {
	let length = u16::try_from(value.len()).unwrap().to_le_bytes();
	hash(&[domain, &[role], &length, value].concat())
}

fn path(role: u8, value: &Path) -> [u8; 32] {
	framed_hash(
		b"ExaCopy/local-sync-genesis-path/v1\0",
		role,
		value.as_os_str().as_bytes(),
	)
}

fn component(role: u8, value: exacopy_endpoint::UnixComponent<'_>) -> [u8; 32] {
	framed_hash(
		b"ExaCopy/local-sync-genesis-component/v1\0",
		role,
		value.as_bytes(),
	)
}

fn hash(input: &[u8]) -> [u8; 32] {
	*blake3::hash(input).as_bytes()
}

pub(super) fn enrollment(request: &ManagedGenesisRequest<'_>, profile: [u8; 16]) -> [u8; 32] {
	let native = request.native;
	let mut bytes = Vec::from(b"ExaCopy/local-sync-genesis-enrollment/v1\0".as_slice());
	bytes.extend(request.enrollment.id);
	bytes.extend(profile);
	bytes.extend(request.owner_key);
	bytes.extend(request.profile_revision.get().to_le_bytes());
	bytes.extend(path(1, request.profile));
	bytes.extend(request.profile_identity.device().to_le_bytes());
	bytes.extend(request.profile_identity.inode().to_le_bytes());
	bytes.extend(path(2, native.parent_path));
	bytes.extend(native.uid.get().to_le_bytes());
	bytes.extend(native.gid.get().to_le_bytes());
	bytes.extend(native.boot);
	append_object(&mut bytes, native.mount_namespace);
	append_object(&mut bytes, native.user_namespace);
	bytes.extend(native.ordinary_mount.get().to_le_bytes());
	bytes.extend(native.unique_mount.get().to_le_bytes());
	append_object(&mut bytes, native.parent);
	bytes.extend(component(1, native.subject));
	for (role, (root, endpoint)) in [2, 3]
		.into_iter()
		.zip(native.roots.into_iter().zip(request.endpoints))
	{
		bytes.extend(endpoint.endpoint);
		bytes.extend(endpoint.root);
		bytes.extend(endpoint.parent);
		bytes.extend(component(role, root.name));
		append_object(&mut bytes, root.identity);
		bytes.extend(endpoint.max_bytes.to_le_bytes());
	}
	bytes.extend(path(3, request.output_parent));
	bytes.extend(request.output_identity.device.to_le_bytes());
	bytes.extend(request.output_identity.inode.get().to_le_bytes());
	bytes.push(u8::try_from(request.enrollment.participants.len()).unwrap());
	for participant in request.enrollment.participants {
		bytes.extend(participant);
	}
	hash(&bytes)
}

pub(super) fn intent(
	request: &ManagedGenesisRequest<'_>,
	profile: [u8; 16],
	root_digest: [u8; 32],
) -> [u8; 32] {
	let native = request.native;
	let mut bytes = Vec::from(b"ExaCopy/local-sync-genesis-approval/v1\0".as_slice());
	bytes.extend(request.operation.bytes());
	bytes.extend(profile);
	bytes.extend(request.owner_key);
	bytes.extend(path(1, request.profile));
	bytes.extend(request.profile_identity.device().to_le_bytes());
	bytes.extend(request.profile_identity.inode().to_le_bytes());
	bytes.extend(path(2, native.parent_path));
	bytes.extend(native.ordinary_mount.get().to_le_bytes());
	bytes.extend(native.uid.get().to_le_bytes());
	bytes.extend(native.gid.get().to_le_bytes());
	bytes.extend(request.enrollment.id);
	bytes.extend(request.enrollment.expected_digest);
	bytes.extend(path(3, request.output_parent));
	bytes.extend(request.output_identity.device.to_le_bytes());
	bytes.extend(request.output_identity.inode.get().to_le_bytes());
	bytes.extend(root_digest);
	hash(&bytes)
}
