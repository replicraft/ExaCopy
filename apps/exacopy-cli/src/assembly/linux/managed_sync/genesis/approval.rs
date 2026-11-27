use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use blake3::Hasher;
use exacopy_endpoint::UnixComponent;
use exacopy_plan::workflow_sync::NativeObject;
use exacopy_platform::linux::{ManagedSyncExpectedObject, SyncGenesisNativeIdentity};

use super::{ManagedGenesisError, ManagedGenesisRequest};

const ENROLLMENT_DOMAIN: &[u8] = b"ExaCopy/local-sync-genesis-enrollment/v1\0";
const APPROVAL_DOMAIN: &[u8] = b"ExaCopy/local-sync-genesis-approval/v1\0";
const PATH_DOMAIN: &[u8] = b"ExaCopy/local-sync-genesis-path/v1\0";
const COMPONENT_DOMAIN: &[u8] = b"ExaCopy/local-sync-genesis-component/v1\0";
const MAX_PATH_BYTES: usize = 4_095;
const MAX_PROFILE_COMPONENTS: usize = 64;
const MAX_ROSTER: usize = 32;

pub(super) struct Approval<'call, 'selection> {
	request: &'call ManagedGenesisRequest<'selection>,
	owner_profile: [u8; 16],
	path_digests: [[u8; 32]; 3],
}

impl<'call, 'selection> Approval<'call, 'selection> {
	pub(super) fn select(
		request: &'call ManagedGenesisRequest<'selection>,
		owner_profile: [u8; 16],
	) -> Result<Self, ManagedGenesisError> {
		if request.profile_identity.inode() == 0
			|| request.enrollment.id == [0; 16]
			|| !valid_roster(request.enrollment.participants)
			|| !coherent_native(request)
		{
			return Err(ManagedGenesisError::Selection);
		}
		let approval = Self {
			request,
			owner_profile,
			path_digests: [
				path_digest(1, request.profile, true)?,
				path_digest(2, request.native.parent_path, false)?,
				path_digest(3, request.output_parent, true)?,
			],
		};
		approval.recheck()?;
		Ok(approval)
	}

	pub(super) fn recheck(&self) -> Result<(), ManagedGenesisError> {
		if self.enrollment_digest() != self.request.enrollment.expected_digest {
			return Err(ManagedGenesisError::Selection);
		}
		Ok(())
	}

	fn enrollment_digest(&self) -> [u8; 32] {
		let request = self.request;
		let native = request.native;
		let [profile, live, output] = self.path_digests;
		let mut hash = Hasher::new();
		hash.update(ENROLLMENT_DOMAIN)
			.update(&request.enrollment.id)
			.update(&self.owner_profile)
			.update(&request.owner_key)
			.update(&request.profile_revision.get().to_le_bytes())
			.update(&profile)
			.update(&request.profile_identity.device().to_le_bytes())
			.update(&request.profile_identity.inode().to_le_bytes())
			.update(&live)
			.update(&native.uid.get().to_le_bytes())
			.update(&native.gid.get().to_le_bytes())
			.update(&native.boot);
		append_native(&mut hash, native.mount_namespace);
		append_native(&mut hash, native.user_namespace);
		hash.update(&native.ordinary_mount.get().to_le_bytes())
			.update(&native.unique_mount.get().to_le_bytes());
		append_native(&mut hash, native.parent);
		hash.update(&component_digest(1, native.subject));
		for (role, (root, endpoint)) in [2, 3]
			.into_iter()
			.zip(native.roots.into_iter().zip(request.endpoints))
		{
			hash.update(&endpoint.endpoint)
				.update(&endpoint.root)
				.update(&endpoint.parent)
				.update(&component_digest(role, root.name));
			append_native(&mut hash, root.identity);
			hash.update(&endpoint.max_bytes.to_le_bytes());
		}
		hash.update(&output);
		append_identity(&mut hash, request.output_identity);
		hash.update(&[
			u8::try_from(request.enrollment.participants.len()).expect("validated roster size")
		]);
		for participant in request.enrollment.participants {
			hash.update(participant);
		}
		*hash.finalize().as_bytes()
	}

	pub(super) fn intent_commitment(&self, root_digest: [u8; 32]) -> [u8; 32] {
		let request = self.request;
		let native = request.native;
		let [profile, live, output] = self.path_digests;
		let mut hash = Hasher::new();
		hash.update(APPROVAL_DOMAIN)
			.update(&request.operation.bytes())
			.update(&self.owner_profile)
			.update(&request.owner_key)
			.update(&profile)
			.update(&request.profile_identity.device().to_le_bytes())
			.update(&request.profile_identity.inode().to_le_bytes())
			.update(&live)
			.update(&native.ordinary_mount.get().to_le_bytes())
			.update(&native.uid.get().to_le_bytes())
			.update(&native.gid.get().to_le_bytes())
			.update(&request.enrollment.id)
			.update(&request.enrollment.expected_digest)
			.update(&output);
		append_identity(&mut hash, request.output_identity);
		hash.update(&root_digest);
		*hash.finalize().as_bytes()
	}
}

fn coherent_native(request: &ManagedGenesisRequest<'_>) -> bool {
	let native = request.native;
	native
		.roots
		.into_iter()
		.zip(request.endpoints)
		.all(|(root, endpoint)| {
			let location = endpoint.location;
			root.name == endpoint.name
				&& same_object(root.identity, location.root)
				&& native.boot == location.boot
				&& same_object(native.mount_namespace, location.mount_namespace)
				&& same_object(native.user_namespace, location.user_namespace)
				&& same_object(native.parent, location.parent)
				&& native.unique_mount == location.mount
		})
}

fn same_object(expected: ManagedSyncExpectedObject, actual: NativeObject) -> bool {
	(expected.major, expected.minor, expected.inode) == (actual.major, actual.minor, actual.inode)
}

fn valid_roster(roster: &[[u8; 16]]) -> bool {
	(1..=MAX_ROSTER).contains(&roster.len())
		&& !roster.contains(&[0; 16])
		&& roster.windows(2).all(|pair| pair[0] < pair[1])
}

fn path_digest(role: u8, path: &Path, profile_path: bool) -> Result<[u8; 32], ManagedGenesisError> {
	let bytes = path.as_os_str().as_bytes();
	if bytes.len() > MAX_PATH_BYTES {
		return Err(ManagedGenesisError::Selection);
	}
	let raw = bytes
		.strip_prefix(b"/")
		.ok_or(ManagedGenesisError::Selection)?;
	let mut components = 0;
	for name in raw.split(|&byte| byte == b'/') {
		UnixComponent::new(name).map_err(|_| ManagedGenesisError::Selection)?;
		components += 1;
	}
	if profile_path && !(2..=MAX_PROFILE_COMPONENTS).contains(&components) {
		return Err(ManagedGenesisError::Selection);
	}
	Ok(digest_raw(PATH_DOMAIN, role, bytes))
}

fn component_digest(role: u8, component: UnixComponent<'_>) -> [u8; 32] {
	digest_raw(COMPONENT_DOMAIN, role, component.as_bytes())
}

fn digest_raw(domain: &[u8], role: u8, bytes: &[u8]) -> [u8; 32] {
	let byte_len = u16::try_from(bytes.len()).expect("validated native component or path size");
	*Hasher::new()
		.update(domain)
		.update(&[role])
		.update(&byte_len.to_le_bytes())
		.update(bytes)
		.finalize()
		.as_bytes()
}

fn append_native(hash: &mut Hasher, object: ManagedSyncExpectedObject) {
	hash.update(&object.major.to_le_bytes())
		.update(&object.minor.to_le_bytes())
		.update(&object.inode.get().to_le_bytes());
}

fn append_identity(hash: &mut Hasher, identity: SyncGenesisNativeIdentity) {
	hash.update(&identity.device.to_le_bytes())
		.update(&identity.inode.get().to_le_bytes());
}
