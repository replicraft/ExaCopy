use std::num::{NonZeroU16, NonZeroU64};

use super::files::MEMBER_LIMIT;
use super::{FileIdentity, SyncGenesisOperation, SyncProfileStoreError};

const MAGIC: [u8; 8] = *b"EXSYNINT";
const VERSION: u16 = 1;
const KINDS: [u16; 4] = [6, 1, 1, 256];
const MEMBER_BYTES: usize = 68;
const HEADER_BYTES: usize = 92;
pub(super) const INTENT_BYTES: usize = HEADER_BYTES + 4 * MEMBER_BYTES;

/// Expected Linux device and inode, independently selected by the application.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SyncGenesisNativeIdentity {
	/// Exact raw Linux device number.
	pub device: u64,
	/// Exact nonzero inode.
	pub inode: NonZeroU64,
}

impl SyncGenesisNativeIdentity {
	/// Encodes independently selected Linux device numbers for an exact inode pin.
	#[must_use]
	pub fn from_device_numbers(major: u32, minor: u32, inode: NonZeroU64) -> Self {
		Self {
			device: rustix::fs::makedev(major, minor),
			inode,
		}
	}

	pub(super) fn matches(self, actual: FileIdentity) -> bool {
		self.device == actual.device() && self.inode.get() == actual.inode()
	}

	fn from_live(actual: FileIdentity) -> Result<Self, SyncProfileStoreError> {
		let inode = NonZeroU64::new(actual.inode()).ok_or(SyncProfileStoreError::Changed)?;
		Ok(Self {
			device: actual.device(),
			inode,
		})
	}
}

/// Canonical and raw commitments to one exact ordered member.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SyncGenesisMemberBinding {
	/// P-063 kind for this ordered slot.
	pub kind: u16,
	/// Exact complete member extent.
	pub byte_len: NonZeroU16,
	/// Existing P-063 body or page digest.
	pub canonical_digest: [u8; 32],
	/// Ordinary BLAKE3 of the complete retained member bytes.
	pub raw_digest: [u8; 32],
}

/// Independently approved app data for one exact publication request.
///
/// The opaque approval commitment carries no publication authority. The
/// application must check it, both digest domains and the live permit
/// independently, including against the actual staged readback.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SyncGenesisIntent {
	/// Independent operation selecting the exact namespace slots.
	pub operation: SyncGenesisOperation,
	/// Expected held output parent.
	pub output: SyncGenesisNativeIdentity,
	/// App approval-and-closure commitment.
	pub approval: [u8; 32],
	/// Ordered exact root, left endpoint, right endpoint and leaf commitments.
	pub members: [SyncGenesisMemberBinding; 4],
}

impl SyncGenesisIntent {
	pub(super) fn validate(
		&self,
		output: FileIdentity,
		members: [&[u8]; 4],
	) -> Result<(), SyncProfileStoreError> {
		if !self.output.matches(output) || !valid_members(&self.members) {
			return Err(SyncProfileStoreError::Changed);
		}
		if self
			.members
			.iter()
			.zip(members)
			.any(|(binding, bytes)| usize::from(binding.byte_len.get()) != bytes.len())
		{
			return Err(SyncProfileStoreError::InvalidExtent);
		}
		Ok(())
	}

	pub(super) fn record(
		&self,
		output: FileIdentity,
		stage: FileIdentity,
	) -> Result<IntentRecord, SyncProfileStoreError> {
		if !self.output.matches(output) {
			return Err(SyncProfileStoreError::Changed);
		}
		IntentRecord::new(*self, SyncGenesisNativeIdentity::from_live(stage)?)
			.ok_or(SyncProfileStoreError::Changed)
	}
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct IntentRecord {
	intent: SyncGenesisIntent,
	stage: SyncGenesisNativeIdentity,
}

impl IntentRecord {
	fn new(intent: SyncGenesisIntent, stage: SyncGenesisNativeIdentity) -> Option<Self> {
		(intent.output.device == stage.device
			&& intent.output.inode != stage.inode
			&& valid_members(&intent.members))
		.then_some(Self { intent, stage })
	}

	pub(super) fn encode(&self) -> [u8; INTENT_BYTES] {
		let mut wire = [0; INTENT_BYTES];
		wire[..8].copy_from_slice(&MAGIC);
		wire[8..10].copy_from_slice(&VERSION.to_le_bytes());
		wire[12..28].copy_from_slice(&self.intent.operation.bytes());
		wire[28..36].copy_from_slice(&self.intent.output.device.to_le_bytes());
		wire[36..44].copy_from_slice(&self.intent.output.inode.get().to_le_bytes());
		wire[44..52].copy_from_slice(&self.stage.device.to_le_bytes());
		wire[52..60].copy_from_slice(&self.stage.inode.get().to_le_bytes());
		wire[60..HEADER_BYTES].copy_from_slice(&self.intent.approval);
		for (entry, member) in wire[HEADER_BYTES..]
			.as_chunks_mut::<MEMBER_BYTES>()
			.0
			.iter_mut()
			.zip(self.intent.members)
		{
			entry[..2].copy_from_slice(&member.kind.to_le_bytes());
			entry[2..4].copy_from_slice(&member.byte_len.get().to_le_bytes());
			entry[4..36].copy_from_slice(&member.canonical_digest);
			entry[36..].copy_from_slice(&member.raw_digest);
		}
		wire
	}

	pub(super) fn decode(wire: &[u8]) -> Option<Self> {
		let wire: &[u8; INTENT_BYTES] = wire.try_into().ok()?;
		if wire[..8] != MAGIC || wire[8..10] != VERSION.to_le_bytes() || wire[10..12] != [0; 2] {
			return None;
		}
		let read_identity = |offset| {
			Some(SyncGenesisNativeIdentity {
				device: u64::from_le_bytes(read(wire, offset)?),
				inode: NonZeroU64::new(u64::from_le_bytes(read(wire, offset + 8)?))?,
			})
		};
		let mut members = wire[HEADER_BYTES..]
			.as_chunks::<MEMBER_BYTES>()
			.0
			.iter()
			.map(read_member);
		let intent = SyncGenesisIntent {
			operation: SyncGenesisOperation::new(read(wire, 12)?)?,
			output: read_identity(28)?,
			approval: read(wire, 60)?,
			members: [
				members.next()??,
				members.next()??,
				members.next()??,
				members.next()??,
			],
		};
		Self::new(intent, read_identity(44)?)
	}
}

fn read<const N: usize>(wire: &[u8], start: usize) -> Option<[u8; N]> {
	wire.get(start..start.checked_add(N)?)?.try_into().ok()
}

fn read_member(wire: &[u8; MEMBER_BYTES]) -> Option<SyncGenesisMemberBinding> {
	Some(SyncGenesisMemberBinding {
		kind: u16::from_le_bytes(read(wire, 0)?),
		byte_len: NonZeroU16::new(u16::from_le_bytes(read(wire, 2)?))?,
		canonical_digest: read(wire, 4)?,
		raw_digest: read(wire, 36)?,
	})
}

fn valid_members(members: &[SyncGenesisMemberBinding; 4]) -> bool {
	members.iter().enumerate().all(|(index, member)| {
		member.kind == KINDS[index]
			&& usize::from(member.byte_len.get()) <= MEMBER_LIMIT
			&& members[..index].iter().all(|previous| {
				previous.canonical_digest != member.canonical_digest
					&& previous.raw_digest != member.raw_digest
			})
	})
}

#[cfg(test)]
mod tests;
