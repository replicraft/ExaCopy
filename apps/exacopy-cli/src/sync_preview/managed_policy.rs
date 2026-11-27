//! Private selection record for the one-subject managed Linux sync preview.

use std::num::{NonZeroU32, NonZeroU64};

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::UnixComponent;
use exacopy_plan::workflow_sync::{
	EndpointFacts, LinuxLocation, MAX_CLOSURE_BYTES, MAX_MEMBER_BYTES, NativeObject, WorkflowKind,
	WorkflowRef, project_pair,
};

mod wire;

#[cfg(test)]
mod tests;

pub(crate) use wire::{decode, encode};

pub(crate) const MANAGED_POLICY_MAX_BYTES: usize = 24 * 1024;
const MAX_PATH_BYTES: usize = 4095;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManagedPolicyIdentity {
	pub(crate) selection_id: [u8; 16],
	pub(crate) revision: NonZeroU64,
	pub(crate) owner_profile: [u8; 16],
	pub(crate) owner_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManagedPolicyPin {
	pub(crate) identity: ManagedPolicyIdentity,
	pub(crate) digest: [u8; 32],
}

impl ManagedPolicyPin {
	/// Constructs the exact decode pin from the independently approved Init inputs.
	pub(crate) fn approved_request(
		selection_id: [u8; 16],
		revision: NonZeroU64,
		owner_key: [u8; 32],
		digest: [u8; 32],
	) -> Result<Self, ManagedPolicyError> {
		if selection_id == [0; 16] || digest == [0; 32] {
			return Err(ManagedPolicyError::Selection);
		}
		let key = canonical_owner_key(&owner_key)?;
		let profile =
			crate::profile::profile_id_for_key(&key).map_err(|_| ManagedPolicyError::Selection)?;
		Ok(Self {
			identity: ManagedPolicyIdentity {
				selection_id,
				revision,
				owner_profile: *profile.as_bytes(),
				owner_key,
			},
			digest,
		})
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Refusal while preparing or admitting the selected managed policy.
pub enum ManagedPolicyError {
	/// The complete policy record exceeds its byte bound.
	Size,
	/// The record does not have the supported canonical encoding.
	Encoding,
	/// The record or owner differs from the approved identity and commitment.
	Selection,
	/// The selected actor, cooperation or live scope is invalid.
	Scope,
	/// The selected historical inventory or directory is invalid.
	History,
}

#[derive(PartialEq, Eq)]
/// Exact approved inputs for one managed Linux synchronization subject.
pub struct ManagedPolicy {
	/// Expected ordinary actor user ID.
	pub actor_uid: NonZeroU32,
	/// Expected ordinary actor group ID.
	pub actor_gid: NonZeroU32,
	/// Independently enrolled cooperation policy for the held parent.
	pub cooperation: ManagedCooperation,
	/// Exact raw absolute path of the managed common parent.
	pub parent_path: Vec<u8>,
	/// Independent common parent capability locator.
	pub parent_locator: [u8; 16],
	/// Expected physical location of the admitted common parent.
	pub location: ManagedPolicyLocation,
	/// Exact raw subject component under each root.
	pub subject: Vec<u8>,
	/// Expected endpoints in the approved left and right order.
	pub endpoints: [ManagedPolicyEndpoint; 2],
	/// Independently selected immutable synchronization history.
	pub history: ManagedPolicyHistory,
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Enrollment for the common-parent exclusive writer discipline.
pub struct ManagedCooperation {
	/// Independently approved nonzero enrollment identifier.
	pub enrollment_id: [u8; 16],
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// Expected Linux native scope facts shared by both endpoints.
pub struct ManagedPolicyLocation {
	/// Expected boot identity.
	pub boot: [u8; 16],
	/// Expected mount namespace device and inode.
	pub mount_namespace: NativeObject,
	/// Expected user namespace device and inode.
	pub user_namespace: NativeObject,
	/// Expected ordinary mount ID.
	pub ordinary_mount: NonZeroU64,
	/// Expected unique mount ID.
	pub unique_mount: NonZeroU64,
	/// Expected common parent device and inode.
	pub parent: NativeObject,
}

#[derive(PartialEq, Eq)]
/// Independent selection of a managed root and its one-subject stream ceiling.
pub struct ManagedPolicyEndpoint {
	/// Approved endpoint identity.
	pub endpoint: [u8; 16],
	/// Approved root capability locator.
	pub root: [u8; 16],
	/// Exact raw child directory name under the common parent.
	pub name: Vec<u8>,
	/// Expected child root device and inode.
	pub object: NativeObject,
	/// Selected maximum stream bytes for this side.
	pub max_bytes: u64,
}

#[derive(PartialEq, Eq)]
/// Exact four-member selection of existing P-063 history.
pub struct ManagedPolicyHistory {
	/// Exact raw absolute path of the separate history directory.
	pub path: Vec<u8>,
	/// Expected history directory device and inode.
	pub directory: NativeObject,
	/// Expected owner-profile revision committed by the history.
	pub revision: NonZeroU64,
	/// Expected signed root resource.
	pub root: ManagedHistoryMember,
	/// Exact child reference-to-name selections for two endpoints and one paired leaf.
	pub children: [ManagedHistoryMember; 3],
	/// Expected historical scan, when independently selected.
	pub scan: Option<NonZeroU64>,
}

#[derive(PartialEq, Eq)]
/// Expected workflow commitment and independent raw resource name.
pub struct ManagedHistoryMember {
	/// Exact raw member basename in the protected history directory.
	pub name: Vec<u8>,
	/// Expected workflow kind, complete extent and digest.
	pub reference: WorkflowRef,
}

fn canonical_owner_key(bytes: &[u8; 32]) -> Result<VerifyingKey, ManagedPolicyError> {
	let key = VerifyingKey::from_bytes(bytes).map_err(|_| ManagedPolicyError::Selection)?;
	if key.is_weak() || key.to_edwards().compress().to_bytes() != *bytes {
		return Err(ManagedPolicyError::Selection);
	}
	Ok(key)
}

impl ManagedPolicyIdentity {
	fn validate(&self) -> Result<(), ManagedPolicyError> {
		if self.selection_id == [0; 16] || self.owner_profile == [0; 16] {
			return Err(ManagedPolicyError::Selection);
		}
		canonical_owner_key(&self.owner_key)?;
		Ok(())
	}
}

impl ManagedPolicy {
	pub(crate) fn endpoint_facts(&self) -> Result<[EndpointFacts<'_>; 2], ManagedPolicyError> {
		let [left, right] = &self.endpoints;
		Ok([
			left.facts(self.parent_locator, self.location)?,
			right.facts(self.parent_locator, self.location)?,
		])
	}

	fn validate(&self, owner_profile: [u8; 16]) -> Result<(), ManagedPolicyError> {
		if !canonical_absolute_path(&self.parent_path) || self.cooperation.enrollment_id == [0; 16]
		{
			return Err(ManagedPolicyError::Scope);
		}
		let subject = UnixComponent::new(&self.subject).map_err(|_| ManagedPolicyError::Scope)?;
		let endpoints = self.endpoint_facts()?;
		project_pair(owner_profile, self.history.revision, subject, endpoints)
			.map_err(|_| ManagedPolicyError::Scope)?;
		if self.history.path == self.parent_path
			|| self.history.directory == self.location.parent
			|| self
				.endpoints
				.iter()
				.any(|endpoint| self.history.directory == endpoint.object)
		{
			return Err(ManagedPolicyError::History);
		}
		self.history.validate()
	}
}

impl ManagedPolicyEndpoint {
	fn facts(
		&self,
		parent: [u8; 16],
		location: ManagedPolicyLocation,
	) -> Result<EndpointFacts<'_>, ManagedPolicyError> {
		let name = UnixComponent::new(&self.name).map_err(|_| ManagedPolicyError::Scope)?;
		Ok(EndpointFacts {
			endpoint: self.endpoint,
			root: self.root,
			parent,
			name,
			location: LinuxLocation {
				boot: location.boot,
				mount_namespace: location.mount_namespace,
				user_namespace: location.user_namespace,
				mount: location.unique_mount,
				parent: location.parent,
				root: self.object,
			},
			max_bytes: self.max_bytes,
		})
	}
}

impl ManagedPolicyHistory {
	fn validate(&self) -> Result<(), ManagedPolicyError> {
		let [left, right, leaf] = &self.children;
		let members = [&self.root, left, right, leaf];
		let kinds = [
			WorkflowKind::Root,
			WorkflowKind::Endpoint,
			WorkflowKind::Endpoint,
			WorkflowKind::Leaf,
		];
		if !canonical_absolute_path(&self.path) {
			return Err(ManagedPolicyError::History);
		}
		let mut total = 0;
		for (index, (member, kind)) in members.iter().zip(kinds).enumerate() {
			let len = usize::from(member.reference.byte_len);
			if member.reference.kind != kind
				|| !(1..=MAX_MEMBER_BYTES).contains(&len)
				|| UnixComponent::new(&member.name).is_err()
				|| members[..index].iter().any(|other| {
					other.name == member.name || other.reference.digest == member.reference.digest
				}) {
				return Err(ManagedPolicyError::History);
			}
			total += len;
		}
		if total > MAX_CLOSURE_BYTES {
			return Err(ManagedPolicyError::History);
		}
		Ok(())
	}
}

fn canonical_absolute_path(path: &[u8]) -> bool {
	path.len() <= MAX_PATH_BYTES
		&& path.strip_prefix(b"/").is_some_and(|relative| {
			relative
				.split(|&byte| byte == b'/')
				.all(|name| UnixComponent::new(name).is_ok())
		})
}
