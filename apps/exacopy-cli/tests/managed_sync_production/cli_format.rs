//! Independent canonical managed policy and receipt wire expectations.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use exacopy_cli::assembly::linux::managed_sync::{
	ManagedHistoryMember, ManagedPolicy, ManagedPolicyEndpoint,
};
use exacopy_plan::workflow_sync::NativeObject;
use serde_json::{Value, json};

use super::TestResult;
use super::cli::{ACK_BYTES, Inputs, REVISION};

#[derive(Clone)]
pub(super) struct Approval {
	path: PathBuf,
	device: u64,
	pub(super) inode: u64,
	pub(super) owner: VerifyingKey,
	owner_profile: [u8; 16],
	pub(super) selection: [u8; 16],
	pub(super) digest: [u8; 32],
	pub(super) envelope: Vec<u8>,
}

impl Approval {
	pub(super) fn new(
		path: &Path,
		device: u64,
		inode: u64,
		selection: [u8; 16],
		selected: &Inputs<'_>,
	) -> TestResult<Self> {
		let owner = selected.signer.verifying_key();
		let approval = hex(&selection);
		let key = hex(owner.as_bytes());
		let policy = wire_policy(selected.owner_profile, selected.policy);
		let projection = serde_json::to_vec(&json!([1, approval, REVISION, key, policy]))?;
		let digest = blake3::derive_key("ExaCopy local managed sync policy v1", &projection);
		let envelope =
			serde_json::to_vec(&json!([1, approval, REVISION, hex(&digest), key, policy]))?;
		Ok(Self {
			path: path.to_owned(),
			device,
			inode,
			owner,
			owner_profile: selected.owner_profile,
			selection,
			digest,
			envelope,
		})
	}

	fn base(&self, command: &str) -> Vec<OsString> {
		let mut args: Vec<OsString> = ["sync-managed", command, "--profile"]
			.map(OsString::from)
			.into();
		args.push(self.path.as_os_str().to_owned());
		args.extend([
			"--owner-key".into(),
			hex(self.owner.as_bytes()).into(),
			"--selection".into(),
			hex(&self.selection).into(),
		]);
		args
	}

	pub(super) fn init(&self) -> Vec<OsString> {
		let mut args = self.base("init");
		args.extend([
			"--profile-device".into(),
			self.device.to_string().into(),
			"--profile-inode".into(),
			self.inode.to_string().into(),
			"--revision".into(),
			REVISION.to_string().into(),
			"--approve-request".into(),
			hex(&self.digest).into(),
			"--request-stdin".into(),
		]);
		args
	}

	pub(super) fn preview(&self) -> Vec<OsString> {
		let mut args = self.base("preview");
		args.push("--receipt-stdin".into());
		args
	}

	pub(super) fn slot(&self) -> String {
		format!("managed-sync-{}.v1", hex(&self.selection))
	}

	pub(super) fn verify(&self, ack: &[u8]) {
		assert_eq!(ack.len(), ACK_BYTES);
		assert_eq!(ack[ACK_BYTES - 1], b'\n');
		let path = blake3::derive_key(
			"ExaCopy local managed sync Init profile path v1",
			self.path.as_os_str().as_bytes(),
		);
		let payload = [
			[1].as_slice(),
			&self.selection,
			&REVISION.to_be_bytes(),
			&self.owner_profile,
			self.owner.as_bytes(),
			&self.device.to_be_bytes(),
			&self.inode.to_be_bytes(),
			&path,
			&self.digest,
		]
		.concat();
		assert_eq!(payload.len(), 153);
		let (framing, signature) = ack[..ACK_BYTES - 1].split_at(payload.len() * 2);
		assert_eq!(framing, hex(&payload).as_bytes());
		let mut raw = [0; 64];
		for (output, chars) in raw.iter_mut().zip(signature.as_chunks::<2>().0) {
			*output = u8::from_str_radix(std::str::from_utf8(chars).unwrap(), 16).unwrap();
		}
		assert_eq!(signature, hex(&raw).as_bytes());
		let message = [
			b"ExaCopy local managed sync Init ack v1\0".as_slice(),
			&payload,
		]
		.concat();
		self.owner
			.verify_strict(&message, &Signature::from_bytes(&raw))
			.unwrap();
	}
}

fn wire_policy(owner: [u8; 16], policy: &ManagedPolicy) -> Value {
	let location = &policy.location;
	let history = &policy.history;
	json!([
		hex(&owner),
		[policy.actor_uid.get(), policy.actor_gid.get()],
		[1, hex(&policy.cooperation.enrollment_id)],
		[
			hex(&policy.parent_path),
			hex(&policy.parent_locator),
			[
				hex(&location.boot),
				native(location.mount_namespace),
				native(location.user_namespace),
				location.ordinary_mount.get(),
				location.unique_mount.get(),
				native(location.parent)
			],
			hex(&policy.subject),
			policy.endpoints.each_ref().map(endpoint),
		],
		[
			hex(&history.path),
			native(history.directory),
			history.revision.get(),
			member(&history.root),
			history.children.each_ref().map(member),
			history.scan.map(std::num::NonZeroU64::get),
		],
	])
}

fn endpoint(ep: &ManagedPolicyEndpoint) -> Value {
	json!([
		hex(&ep.endpoint),
		hex(&ep.root),
		hex(&ep.name),
		native(ep.object),
		ep.max_bytes
	])
}

fn native(native: NativeObject) -> Value {
	json!([native.major, native.minor, native.inode.get()])
}

fn member(member: &ManagedHistoryMember) -> Value {
	let reference = member.reference;
	json!([
		hex(&member.name),
		reference.kind as u16,
		reference.byte_len,
		hex(&reference.digest)
	])
}

pub(super) fn hex(value: &[u8]) -> String {
	let mut result = String::with_capacity(2 * value.len());
	for byte in value {
		write!(result, "{byte:02x}").unwrap();
	}
	result
}
