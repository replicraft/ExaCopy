//! Held, owner-private Linux publication of exactly one genesis closure.

use std::fs::File;
use std::io;
use std::path::Path;

use rustix::fs::{self, AtFlags, FlockOperation, RenameFlags};
use rustix::io::Errno;

use super::pin::Pin;
use super::{PRIVATE_DIRECTORY, SyncProfileSeed, SyncProfileStore, SyncProfileStoreError};
use crate::linux::sync_preview::unique_mount_id;
use crate::linux::{FileIdentity, ManagedSyncPreviewPair, SyncPreviewEntry};

mod error;
mod files;
mod intent;
mod operation;
mod recovery_observation;

pub use error::SyncGenesisPublishError;
pub use intent::{SyncGenesisIntent, SyncGenesisMemberBinding, SyncGenesisNativeIdentity};
pub use operation::SyncGenesisOperation;
pub use recovery_observation::{
	SyncGenesisRecoveryDisposition, SyncGenesisRecoveryExpectation, SyncGenesisRecoveryIssue,
	SyncGenesisRecoveryObservation, SyncGenesisRecoverySession, SyncGenesisRecoverySlots,
};

use files::{Stage, StageDirectory, create_record};
use intent::{INTENT_BYTES, IntentRecord};

/// A fixed member of the four-item signed genesis closure.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(usize)]
pub enum SyncGenesisMember {
	/// Signed root.
	Root,
	/// Signed left endpoint binding.
	Left,
	/// Signed right endpoint binding.
	Right,
	/// Canonical paired baseline leaf.
	Leaf,
}

/// One exact native action requiring application admission.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SyncGenesisEffect {
	/// Exclusively creates the fixed private staging directory.
	CreateStage,
	/// Exclusively creates the exact indicated regular file.
	CreateMember(SyncGenesisMember),
	/// Writes the once-selected bounded member.
	WriteMember(SyncGenesisMember),
	/// Requests a barrier on the exact written file.
	SyncMember(SyncGenesisMember),
	/// Requests a barrier on the sealed staging directory.
	SyncStage,
	/// Exclusively creates the independently selected private intent slot.
	CreateIntent,
	/// Writes the bounded exact publication intent.
	WriteIntent,
	/// Requests a barrier on the written intent record.
	SyncIntent,
	/// Requests the parent barrier before the rename.
	SyncParentBeforeRename,
	/// Renames only the exact stage to the absent target with no replacement.
	Rename,
	/// Requests the parent barrier after the known successful rename.
	SyncParentAfterRename,
	/// Confirms current app custody before issuing the final acknowledgment.
	ConfirmPublication,
}

/// Current native effect and its exact independently selected binding.
#[derive(Clone, Copy)]
pub struct SyncGenesisEffectRequest<'intent> {
	/// Exact effect to admit.
	pub effect: SyncGenesisEffect,
	/// Immutable owner-selected intent and member commitments.
	pub intent: &'intent SyncGenesisIntent,
	/// Exact held output directory.
	pub output: FileIdentity,
	/// The original stage identity, if it has been established.
	pub stage: Option<FileIdentity>,
}

/// Four exact bounded artifact bytes, ordered root, left, right and leaf.
pub struct SyncGenesisPublishRequest<'intent> {
	/// Independently approved publication intent.
	pub intent: &'intent SyncGenesisIntent,
	/// Exact data retained by the application for verification and publication.
	pub members: [&'intent [u8]; 4],
}

/// Completed observation after publication and the requested barriers.
pub struct SyncGenesisPublished {
	/// Selected operation and its unique final basename derivation.
	pub operation: SyncGenesisOperation,
	/// Original staged directory, observed through its final name.
	pub identity: FileIdentity,
}

/// Held protected output parent for one namespace-atomic genesis publication.
pub struct SyncGenesisOutput {
	parent: SyncProfileStore,
}

impl SyncGenesisOutput {
	/// Holds the independently selected existing output parent without mutation.
	///
	/// # Errors
	/// Refuses changes to the selected identity, private ancestry or mount.
	pub fn open(
		path: &Path,
		expected: SyncGenesisNativeIdentity,
	) -> Result<Self, SyncProfileStoreError> {
		let parent = SyncProfileStore::open(path)?;
		if !expected.matches(parent.identity()) {
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(Self { parent })
	}

	/// Publishes one sealed four-member directory under the exact selected operation.
	///
	/// The caller independently approves the scope and member digests, verifies the
	/// closure and supplies a live gate for every native effect. The gate returns
	/// its serialization guard, held through the individual effect. The provisioner
	/// excludes noncooperating writers and retained writable aliases, and the held
	/// profile and live lease remain borrowed through final checks.
	///
	/// # Errors
	/// Refuses any unadmitted effect or drift, and preserves all staged or uncertain
	/// artifacts. A final receipt requires successful barriers and exact observations.
	pub fn publish<G>(
		&self,
		seed: &SyncProfileSeed<'_>,
		live: &ManagedSyncPreviewPair<'_, '_>,
		request: SyncGenesisPublishRequest<'_>,
		verify_staged: impl FnOnce([&[u8]; 4]) -> io::Result<()>,
		mut enter: impl FnMut(SyncGenesisEffectRequest<'_>) -> io::Result<G>,
	) -> Result<SyncGenesisPublished, SyncGenesisPublishError> {
		let members = request.members;
		let intent = request.intent;
		let operation = intent.operation;
		let output = self.parent.identity();
		let before_stage = |cause| pre_submission(operation, None, cause);
		intent.validate(output, members).map_err(before_stage)?;

		let owner = self.parent.owner;
		let mount = self.parent.mount;
		let final_name = operation.final_name();
		let stage_name = operation.stage_name();
		let intent_name = operation.intent_name();
		let recheck = || self.recheck(seed, live);
		recheck().map_err(before_stage)?;
		let parent = self
			.parent
			.lease(FlockOperation::NonBlockingLockExclusive)
			.map_err(before_stage)?;
		recheck().map_err(before_stage)?;
		let check_initial_names = || {
			for name in [&final_name, &stage_name, &intent_name] {
				require_absent(&parent, name)?;
			}
			Ok(())
		};
		check_initial_names().map_err(before_stage)?;
		{
			let _guard = enter(SyncGenesisEffectRequest {
				effect: SyncGenesisEffect::CreateStage,
				intent,
				output,
				stage: None,
			})
			.map_err(|error| before_stage(error.into()))?;
			recheck().map_err(before_stage)?;
			check_initial_names().map_err(before_stage)?;
			fs::mkdirat(&parent, &stage_name, PRIVATE_DIRECTORY)
				.map_err(|error| pre_submission(operation, None, error.into()))?;
		}
		let stage = StageDirectory::open(&parent, &stage_name, owner, mount)
			.map_err(|error| pre_submission(operation, None, error))?;
		let original = stage.identity;
		let mut admit = |effect| {
			let guard = enter(SyncGenesisEffectRequest {
				effect,
				intent,
				output,
				stage: Some(original),
			})?;
			recheck()?;
			Ok::<_, SyncProfileStoreError>(guard)
		};
		let retain = |error| pre_submission(operation, Some(original), error);
		let stage = stage
			.populate(&parent, &stage_name, members, owner, mount, &mut admit)
			.map_err(retain)?;
		stage.verify(members, verify_staged).map_err(retain)?;
		stage
			.recheck(&parent, &stage_name, members, owner, mount)
			.map_err(retain)?;
		{
			let _guard = admit(SyncGenesisEffect::SyncStage).map_err(retain)?;
			stage
				.recheck(&parent, &stage_name, members, owner, mount)
				.map_err(retain)?;
			fs::fsync(&stage.directory).map_err(|error| retain(error.into()))?;
		}
		stage
			.recheck(&parent, &stage_name, members, owner, mount)
			.map_err(retain)?;
		let intent_record = intent.record(output, original).map_err(retain)?;
		let wire = intent_record.encode();
		let record = create_record(&parent, &intent_name, &wire, owner, mount, None, &mut admit)
			.map_err(retain)?;
		{
			let _guard = admit(SyncGenesisEffect::SyncParentBeforeRename).map_err(retain)?;
			fs::fsync(&parent).map_err(|error| retain(error.into()))?;
		}

		let sealed = SealedSubmission {
			parent: &parent,
			output,
			stage_name: &stage_name,
			final_name: &final_name,
			stage: &stage,
			intent: &record,
			intent_bytes: &wire,
			intent_record: &intent_record,
			members,
			owner,
			mount,
		};
		let permit = RenamePermit {
			sealed: &sealed,
			operation,
		};
		permit.submit(&mut admit)?;

		let uncertain = |cause| SyncGenesisPublishError::KernelSuccessLaterUncertain {
			operation,
			stage: original,
			cause,
		};
		let observe_publication = || sealed.observe_published();
		observe_publication().map_err(uncertain)?;
		{
			let _guard = admit(SyncGenesisEffect::SyncParentAfterRename).map_err(uncertain)?;
			observe_publication().map_err(uncertain)?;
			fs::fsync(&parent).map_err(|error| uncertain(error.into()))?;
		}
		let _acknowledgment = admit(SyncGenesisEffect::ConfirmPublication).map_err(uncertain)?;
		observe_publication().map_err(uncertain)?;
		recheck().map_err(uncertain)?;
		Ok(SyncGenesisPublished {
			operation,
			identity: original,
		})
	}

	fn recheck(
		&self,
		seed: &SyncProfileSeed<'_>,
		live: &ManagedSyncPreviewPair<'_, '_>,
	) -> Result<(), SyncProfileStoreError> {
		let roots = live.held_roots();
		let (_, facts) = live.recheck_history_location().map_err(io::Error::other)?;
		let unique = facts[0].unique_mount;
		if unique_mount_id(&self.parent.profile().file).map_err(io::Error::other)? != unique
			|| self.parent.mount != roots.selection().mount_id
			|| self.parent.owner != seed.store.owner
		{
			return Err(SyncProfileStoreError::Changed);
		}
		if !live
			.entries()
			.iter()
			.all(|entry| matches!(entry, SyncPreviewEntry::Present(_)))
		{
			return Err(SyncProfileStoreError::Changed);
		}
		seed.store
			.check_genesis_output_disjoint(&self.parent, roots)?;
		let (_, latest) = live.recheck_history_location().map_err(io::Error::other)?;
		if latest != facts {
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(())
	}
}

fn require_absent(parent: &File, name: &[u8]) -> Result<(), SyncProfileStoreError> {
	match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
		Err(Errno::NOENT) => Ok(()),
		Ok(_) => Err(SyncProfileStoreError::AlreadyExists),
		Err(error) => Err(error.into()),
	}
}

fn pre_submission(
	operation: SyncGenesisOperation,
	stage: Option<FileIdentity>,
	cause: SyncProfileStoreError,
) -> SyncGenesisPublishError {
	SyncGenesisPublishError::PreSubmission {
		operation,
		stage,
		cause,
	}
}

struct SealedSubmission<'files> {
	parent: &'files File,
	output: FileIdentity,
	stage_name: &'files [u8],
	final_name: &'files [u8],
	stage: &'files Stage,
	intent: &'files Pin,
	intent_bytes: &'files [u8; INTENT_BYTES],
	intent_record: &'files IntentRecord,
	members: [&'files [u8]; 4],
	owner: u32,
	mount: u64,
}

impl SealedSubmission<'_> {
	fn check_parent_and_intent(&self) -> Result<(), SyncProfileStoreError> {
		let output = super::DirectoryStamp::observe(self.parent, self.owner)?;
		if output.identity != self.output
			|| output.owner != self.owner
			|| output.mode != PRIVATE_DIRECTORY
			|| super::mount_id(self.parent)? != self.mount
		{
			return Err(SyncProfileStoreError::Changed);
		}
		let mut readback = [0; INTENT_BYTES];
		self.intent.read(self.parent, &mut readback, &mut [0])?;
		if &readback != self.intent_bytes
			|| IntentRecord::decode(&readback).as_ref() != Some(self.intent_record)
		{
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(())
	}

	fn observe_published(&self) -> Result<(), SyncProfileStoreError> {
		self.check_parent_and_intent()?;
		require_absent(self.parent, self.stage_name)?;
		self.stage.recheck(
			self.parent,
			self.final_name,
			self.members,
			self.owner,
			self.mount,
		)
	}
}

// This private token owns the only submission transition. The read-only
// seals remain borrowed for observation and cannot issue another rename.
struct RenamePermit<'files> {
	sealed: &'files SealedSubmission<'files>,
	operation: SyncGenesisOperation,
}

impl RenamePermit<'_> {
	fn submit<G>(
		self,
		admit: &mut impl FnMut(SyncGenesisEffect) -> Result<G, SyncProfileStoreError>,
	) -> Result<(), SyncGenesisPublishError> {
		let Self { sealed, operation } = self;
		let stage = sealed.stage.identity;
		let before = |cause| pre_submission(operation, Some(stage), cause);
		let _guard = admit(SyncGenesisEffect::Rename).map_err(before)?;
		sealed.check_parent_and_intent().map_err(before)?;
		sealed
			.stage
			.recheck(
				sealed.parent,
				sealed.stage_name,
				sealed.members,
				sealed.owner,
				sealed.mount,
			)
			.map_err(before)?;
		match fs::renameat_with(
			sealed.parent,
			sealed.stage_name,
			sealed.parent,
			sealed.final_name,
			RenameFlags::NOREPLACE,
		) {
			Ok(()) => Ok(()),
			Err(Errno::EXIST) => Err(SyncGenesisPublishError::KernelExists { operation, stage }),
			Err(error) => Err(SyncGenesisPublishError::SubmittedUnknown {
				operation,
				stage,
				cause: error.into(),
			}),
		}
	}
}
