//! Fixed V1 identity preimages from the original checked native roles.

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};

use crate::linux::{FileIdentity, job::FIRST_SEGMENT};

use super::PreparedActionRoleFacts;

const SLOT_PREFIX_BYTES: usize = 105;
const MAX_ROLE_BYTES: usize =
	SLOT_PREFIX_BYTES + MAX_UNIX_COMPONENT_BYTES + 16 + FIRST_SEGMENT.len();
const _: () = assert!(MAX_UNIX_COMPONENT_BYTES == u8::MAX as usize);
const _: () = assert!(FIRST_SEGMENT.len() == 27);

/// Exact V1 preimages for the original managed action slot and segment.
///
/// These byte strings describe observed identities. They carry no execution
/// authority or statement about barrier completion. The application commits
/// each preimage in its separately selected versioned hash context.
pub struct PreparedActionRoleBytes {
	bytes: [u8; MAX_ROLE_BYTES],
	slot_end: usize,
	segment_end: usize,
}

impl PreparedActionRoleBytes {
	/// Returns the canonical original slot preimage.
	#[must_use]
	pub fn slot(&self) -> &[u8] {
		&self.bytes[..self.slot_end]
	}

	/// Returns the canonical original segment preimage.
	#[must_use]
	pub fn segment(&self) -> &[u8] {
		&self.bytes[..self.segment_end]
	}
}

impl PreparedActionRoleFacts<'_> {
	/// Encodes exact V1 identity fields obtained by the original held guard.
	#[must_use]
	pub fn role_projection_bytes(&self) -> PreparedActionRoleBytes {
		let identity = |value: FileIdentity| [value.device(), value.inode()];
		RoleInput {
			boot: self.boot(),
			namespaces: [
				identity(self.mount_namespace()),
				identity(self.user_namespace()),
			],
			mounts: [self.ordinary_mount().get(), self.unique_mount().get()],
			actor: [self.uid().get(), self.gid().get()],
			profile: identity(self.profile()),
			slot: identity(self.slot()),
			name: self.name(),
			segment: identity(self.segment()),
		}
		.encode()
	}
}

struct RoleInput<'name> {
	boot: [u8; 16],
	namespaces: [[u64; 2]; 2],
	mounts: [u64; 2],
	actor: [u32; 2],
	profile: [u64; 2],
	slot: [u64; 2],
	name: UnixComponent<'name>,
	segment: [u64; 2],
}

impl RoleInput<'_> {
	fn encode(self) -> PreparedActionRoleBytes {
		let mut bytes = [0; MAX_ROLE_BYTES];
		let mut position = 0;
		put(&mut bytes, &mut position, &self.boot);
		for value in self.namespaces.into_iter().flatten().chain(self.mounts) {
			put(&mut bytes, &mut position, &value.to_le_bytes());
		}
		for value in self.actor {
			put(&mut bytes, &mut position, &value.to_le_bytes());
		}
		for value in self.profile.into_iter().chain(self.slot) {
			put(&mut bytes, &mut position, &value.to_le_bytes());
		}
		let name = self.name.as_bytes();
		let length = u8::try_from(name.len()).expect("a validated component fits one byte");
		put(&mut bytes, &mut position, &[length]);
		debug_assert_eq!(position, SLOT_PREFIX_BYTES);
		put(&mut bytes, &mut position, name);
		let slot_end = position;
		for value in self.segment {
			put(&mut bytes, &mut position, &value.to_le_bytes());
		}
		put(&mut bytes, &mut position, FIRST_SEGMENT.as_bytes());
		PreparedActionRoleBytes {
			bytes,
			slot_end,
			segment_end: position,
		}
	}
}

fn put(output: &mut [u8; MAX_ROLE_BYTES], position: &mut usize, field: &[u8]) {
	let end = *position + field.len();
	output[*position..end].copy_from_slice(field);
	*position = end;
}

#[cfg(test)]
mod tests;
