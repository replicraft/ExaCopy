use std::fs::File;
use std::io;
use std::num::NonZeroU64;

use rustix::fs::{self, AtFlags, FlockOperation, OFlags};
use rustix::io::Errno;

use super::files::{
	MEMBER_LIMIT, MEMBER_NAMES, StageDirectory, check_inventory, recheck_record, require_directory,
};
use super::{
	FileIdentity, INTENT_BYTES, IntentRecord, Pin, SyncGenesisIntent, SyncGenesisNativeIdentity,
	SyncGenesisOperation, SyncGenesisOutput, SyncProfileStoreError,
};
use crate::linux::mount_observation::ProcMounts;
use crate::linux::process_crash::{KERNEL_BOOT_ID_BYTES, parse_boot_id};
use crate::linux::sync_preview::{HeldNamespaces, unique_mount_id};

/// Current native session independently pinned for exact attempt observation.
#[derive(Clone, Copy, Debug)]
pub struct SyncGenesisRecoverySession {
	/// Expected boot UUID.
	pub boot: [u8; 16],
	/// Expected mount namespace identity.
	pub mount_namespace: SyncGenesisNativeIdentity,
	/// Expected user namespace identity.
	pub user_namespace: SyncGenesisNativeIdentity,
	/// Expected unique mount ID for the protected output.
	pub unique_mount: NonZeroU64,
}

/// Independent pins for one original genesis attempt.
#[derive(Clone, Copy, Debug)]
pub struct SyncGenesisRecoveryExpectation<'pins> {
	/// Exact intent selected independently of the observed files.
	pub intent: &'pins SyncGenesisIntent,
	/// Independently retained original stage identity, including after a rename.
	pub stage: SyncGenesisNativeIdentity,
	/// Independently retained native session.
	pub session: SyncGenesisRecoverySession,
}

/// Exact current occupancy of the operation's three names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncGenesisRecoverySlots {
	/// Inode observed at the final name, even if it fails the private profile.
	pub published: Option<FileIdentity>,
	/// Inode observed at the private staging name.
	pub stage: Option<FileIdentity>,
	/// Inode observed at the private intent name.
	pub intent: Option<FileIdentity>,
}

/// Reason the current observations cannot identify a complete original attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum SyncGenesisRecoveryIssue {
	/// Both candidate directory names are occupied.
	MultipleCandidates,
	/// The caller has no independently retained exact attempt evidence.
	IndependentEvidenceUnavailable,
	/// The selected candidate is absent while the intent name remains occupied.
	OrphanedIntent,
	/// The final name exists without an intent.
	MissingIntent,
	/// The exact named directory differs from the independently pinned stage.
	OriginalStageMismatch,
	/// Independently required current native session differs.
	Session,
	/// Native custody, expected extent or intent validation failed.
	Native(SyncProfileStoreError),
	/// The caller-supplied verifier refused the selected bytes.
	Closure(io::Error),
}

/// Bounded observation of current state. It conveys no previous syscall or barrier result.
#[derive(Debug)]
#[non_exhaustive]
pub enum SyncGenesisRecoveryDisposition {
	/// All three selected names are confirmed absent.
	AllAbsent,
	/// The independently pinned private stage name remains and the intent is absent.
	///
	/// This is namespace evidence. Directory contents were not checked.
	PinnedStageNameWithoutIntent,
	/// The current staged directory matches the retained inode and extent pins.
	///
	/// The caller-supplied verifier also accepted the bytes.
	StageBytesObserved,
	/// The current final directory matches the retained inode and extent pins.
	///
	/// The caller-supplied verifier also accepted the bytes.
	FinalBytesObserved,
	/// Current selected names do not support a positive classification.
	Unresolved(SyncGenesisRecoveryIssue),
}

/// Current operation-scoped observations without a publication or selection receipt.
#[derive(Debug)]
pub struct SyncGenesisRecoveryObservation {
	/// Independently selected operation.
	pub operation: SyncGenesisOperation,
	/// Stable occupancy of only its three exact names.
	pub slots: SyncGenesisRecoverySlots,
	/// Evidence supported by this observation.
	pub disposition: SyncGenesisRecoveryDisposition,
}

impl SyncGenesisOutput {
	/// Observes only this operation's three exact names under a shared cooperating lease.
	///
	/// Positive exact states require separately retained original stage, session and intent
	/// pins. A device and inode match is a current comparison and establishes no
	/// continuity across an unheld interval. The caller supplies the verifier; this
	/// layer reads and rechecks the exact bytes under the native lease. If no pins
	/// were retained, occupied names yield advisory occupancy only. This method creates no
	/// receipt and performs no repair, promotion, barrier, or history selection.
	///
	/// # Errors
	/// Refuses an unavailable lease, invalid independent inputs, or unstable slot custody.
	pub fn observe_recovery(
		&self,
		operation: SyncGenesisOperation,
		expected: Option<SyncGenesisRecoveryExpectation<'_>>,
		verify: impl FnOnce([&[u8]; 4]) -> io::Result<()>,
	) -> Result<SyncGenesisRecoveryObservation, SyncProfileStoreError> {
		if expected.is_some_and(|expected| {
			expected.intent.operation != operation
				|| !expected.intent.output.matches(self.parent.identity())
				|| expected.stage.device != expected.intent.output.device
				|| expected.stage.inode == expected.intent.output.inode
		}) {
			return Err(SyncProfileStoreError::InvalidSelection);
		}
		let parent = self.parent.lease(FlockOperation::NonBlockingLockShared)?;
		let namespaces = HeldNamespaces::current().map_err(io::Error::other)?;
		let names = Names {
			published: operation.final_name(),
			stage: operation.stage_name(),
			intent: operation.intent_name(),
		};
		let slots = names.observe(&parent)?;
		let state = Observation {
			output: self,
			parent: &parent,
			namespaces: &namespaces,
			names: &names,
			slots,
		};
		state.recheck()?;
		let check_session = || expected.map_or(Ok(()), |pins| state.check_session(pins.session));
		let disposition = check_session()
			.map(|()| state.classify(expected, verify))
			.and_then(|observed| {
				check_session()?;
				Ok(observed)
			})
			.unwrap_or_else(SyncGenesisRecoveryDisposition::Unresolved);
		state.recheck()?;
		Ok(SyncGenesisRecoveryObservation {
			operation,
			slots,
			disposition,
		})
	}
}

struct Names {
	published: Vec<u8>,
	stage: Vec<u8>,
	intent: Vec<u8>,
}

impl Names {
	fn observe(&self, parent: &File) -> Result<SyncGenesisRecoverySlots, SyncProfileStoreError> {
		Ok(SyncGenesisRecoverySlots {
			published: lookup(parent, &self.published)?,
			stage: lookup(parent, &self.stage)?,
			intent: lookup(parent, &self.intent)?,
		})
	}
}

fn lookup(parent: &File, name: &[u8]) -> Result<Option<FileIdentity>, SyncProfileStoreError> {
	match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
		Ok(stat) => Ok(Some(FileIdentity::from_stat(&stat))),
		Err(Errno::NOENT) => Ok(None),
		Err(error) => Err(error.into()),
	}
}

struct Observation<'held> {
	output: &'held SyncGenesisOutput,
	parent: &'held File,
	namespaces: &'held HeldNamespaces,
	names: &'held Names,
	slots: SyncGenesisRecoverySlots,
}

impl Observation<'_> {
	fn recheck(&self) -> Result<(), SyncProfileStoreError> {
		self.output.parent.recheck()?;
		self.namespaces
			.recheck_current()
			.map_err(io::Error::other)?;
		if self.names.observe(self.parent)? != self.slots {
			return Err(SyncProfileStoreError::Changed);
		}
		self.output.parent.recheck()
	}

	fn check_session(
		&self,
		session: SyncGenesisRecoverySession,
	) -> Result<(), SyncGenesisRecoveryIssue> {
		self.namespaces
			.recheck_current()
			.map_err(io::Error::other)
			.map_err(SyncProfileStoreError::from)
			.map_err(SyncGenesisRecoveryIssue::Native)?;
		let namespaces = self.namespaces.facts();
		let read_session = || -> Result<_, SyncProfileStoreError> {
			let proc = ProcMounts::open()?;
			let boot = proc.root_file(c"sys/kernel/random/boot_id", KERNEL_BOOT_ID_BYTES)?;
			let unique = unique_mount_id(self.parent).map_err(io::Error::other)?;
			Ok((boot, unique))
		};
		let (boot, unique) = read_session().map_err(SyncGenesisRecoveryIssue::Native)?;
		if parse_boot_id(&boot) != Some(session.boot)
			|| !session.mount_namespace.matches(namespaces.mount)
			|| !session.user_namespace.matches(namespaces.user)
			|| unique != session.unique_mount
		{
			return Err(SyncGenesisRecoveryIssue::Session);
		}
		Ok(())
	}

	fn classify(
		&self,
		expected: Option<SyncGenesisRecoveryExpectation<'_>>,
		verify: impl FnOnce([&[u8]; 4]) -> io::Result<()>,
	) -> SyncGenesisRecoveryDisposition {
		use SyncGenesisRecoveryDisposition as State;
		use SyncGenesisRecoveryIssue as Issue;

		match (self.slots.published, self.slots.stage, self.slots.intent) {
			(None, None, None) => State::AllAbsent,
			(Some(_), Some(_), _) => State::Unresolved(Issue::MultipleCandidates),
			(None, None, Some(_)) => State::Unresolved(Issue::OrphanedIntent),
			(Some(_), None, None) => State::Unresolved(Issue::MissingIntent),
			_ => {
				let Some(expected) = expected else {
					return State::Unresolved(Issue::IndependentEvidenceUnavailable);
				};
				self.classify_pinned(expected, verify)
					.unwrap_or_else(State::Unresolved)
			}
		}
	}

	fn classify_pinned(
		&self,
		expected: SyncGenesisRecoveryExpectation<'_>,
		verify: impl FnOnce([&[u8]; 4]) -> io::Result<()>,
	) -> Result<SyncGenesisRecoveryDisposition, SyncGenesisRecoveryIssue> {
		use SyncGenesisRecoveryDisposition as State;
		use SyncGenesisRecoveryIssue as Issue;

		let (name, candidate, exact) = if let Some(published) = self.slots.published {
			(&self.names.published, published, State::FinalBytesObserved)
		} else {
			(
				&self.names.stage,
				self.slots.stage.ok_or(Issue::OrphanedIntent)?,
				State::StageBytesObserved,
			)
		};
		let owner = self.output.parent.owner;
		let mount = self.output.parent.mount;
		let directory =
			StageDirectory::open(self.parent, name, owner, mount).map_err(Issue::Native)?;
		check_original(expected.stage, candidate, directory.identity)?;
		let intent_identity = match self.slots.intent {
			Some(identity) => identity,
			None => {
				require_directory(self.parent, name, &directory.file, candidate, owner, mount)
					.map_err(Issue::Native)?;
				self.check_session(expected.session)?;
				self.recheck().map_err(Issue::Native)?;
				return Ok(State::PinnedStageNameWithoutIntent);
			}
		};
		let intent =
			Pin::open(self.parent, &self.names.intent, owner, mount).map_err(Issue::Native)?;
		let mut wire = [0; INTENT_BYTES];
		intent
			.read(self.parent, &mut wire, &mut [0])
			.map_err(Issue::Native)?;
		let expected_record = expected
			.intent
			.record(self.output.parent.identity(), directory.identity)
			.map_err(Issue::Native)?;
		if intent.stamp.identity != intent_identity
			|| IntentRecord::decode(&wire).as_ref() != Some(&expected_record)
		{
			return Err(Issue::Native(SyncProfileStoreError::Changed));
		}

		let mut storage = [[0; MEMBER_LIMIT]; 4];
		let [root, left, right, leaf] = &mut storage;
		let open_member = |index: usize, storage: &mut [u8; MEMBER_LIMIT]| {
			let name = MEMBER_NAMES[index];
			let binding = expected.intent.members[index];
			let extent = storage
				.get_mut(..usize::from(binding.byte_len.get()))
				.ok_or(Issue::Native(SyncProfileStoreError::InvalidExtent))?;
			let pin = Pin::open(&directory.file, name, owner, mount).map_err(Issue::Native)?;
			pin.read(&directory.file, extent, &mut [0])
				.map_err(Issue::Native)?;
			Ok(pin)
		};
		let files = [
			open_member(0, root)?,
			open_member(1, left)?,
			open_member(2, right)?,
			open_member(3, leaf)?,
		];
		let identities = files.each_ref().map(|pin| pin.stamp.identity);
		check_inventory(&directory.file, identities, OFlags::NOATIME).map_err(Issue::Native)?;
		let members = std::array::from_fn(|index| {
			&storage[index][..usize::from(expected.intent.members[index].byte_len.get())]
		});
		verify(members).map_err(Issue::Closure)?;
		for (pin, bytes) in files.iter().zip(members) {
			recheck_record(&directory.file, pin, bytes).map_err(Issue::Native)?;
		}
		check_inventory(&directory.file, identities, OFlags::NOATIME).map_err(Issue::Native)?;
		recheck_record(self.parent, &intent, &wire).map_err(Issue::Native)?;
		require_directory(self.parent, name, &directory.file, candidate, owner, mount)
			.map_err(Issue::Native)?;
		self.check_session(expected.session)?;
		self.recheck().map_err(Issue::Native)?;
		Ok(exact)
	}
}

fn check_original(
	expected: SyncGenesisNativeIdentity,
	named: FileIdentity,
	held: FileIdentity,
) -> Result<(), SyncGenesisRecoveryIssue> {
	if named != held || !expected.matches(held) {
		return Err(SyncGenesisRecoveryIssue::OriginalStageMismatch);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_rewritten_intent_cannot_substitute_an_independently_pinned_stage() {
		let named = FileIdentity::from_stat(&fs::stat(".").unwrap());
		let matching = SyncGenesisNativeIdentity {
			device: named.device(),
			inode: NonZeroU64::new(named.inode()).unwrap(),
		};
		check_original(matching, named, named).unwrap();

		let original = SyncGenesisNativeIdentity {
			inode: NonZeroU64::new(if matching.inode.get() == 1 { 2 } else { 1 }).unwrap(),
			..matching
		};
		// Even if every signed member and the observed intent agree with the
		// candidate, native admission compares the unrelated independent pin.
		assert!(matches!(
			check_original(original, named, named),
			Err(SyncGenesisRecoveryIssue::OriginalStageMismatch)
		));
	}
}
