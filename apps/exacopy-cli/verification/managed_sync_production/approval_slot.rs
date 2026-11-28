//! Owned native prepared-origin and custody controls for the approval SDK.

use std::cell::Cell;
use std::fs::File;
use std::num::NonZeroUsize;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};

use exacopy_cli::assembly::linux::CopyRoots;
use exacopy_cli::assembly::linux::managed_sync::ManagedSyncPreviewError;
use exacopy_cli::assembly::linux::managed_sync::activation::{
	ApprovalEnrollment, ApprovalError, ApprovalInput, ApprovalReview, ApprovalSelection,
	PreparedApprovalInput, PreparedRecreate, with_scoped_prepared_recreate,
};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameWriter};
use exacopy_journal::managed_action_prepared::{
	MANAGED_ACTION_PREPARED_FRAME_BYTES, ManagedActionPrepared, encode_managed_action_prepared,
};
use exacopy_journal::managed_activation_claim::ManagedActivationChild;
use exacopy_journal::{ApprovedPublicPlanDigest, PublicPlanEntryId};
use exacopy_model::SyncSide;
use exacopy_plan::UnixTimestamp;
use exacopy_platform::linux::{
	ManagedSyncError, ManagedSyncExpectedObject, PreparedActionSlotSelection,
	PreparedManagedActionError, SyncPreviewError, SyncProfileStoreError,
};
use rustix::fs::{FlockOperation, OFlags, StatxFlags, flock, major, makedev, minor};
use rustix::process::{getegid, geteuid};

use super::{Sandbox, TestResult};
use crate::rig::{MOUNT_ID_UNIQUE, assert_missing, kernel_location, mount_id, open_child, read};
use crate::{ROOT_NAMES, SUBJECT};

#[path = "approval_slot_edges.rs"]
pub(super) mod edges;
#[path = "approval_host_refusals.rs"]
mod host_refusals;

const SLOT: &[u8] = b"approval-fixture-slot";
const SEGMENT: &[u8] = b"00000000000000000001.exajnl";
const RETAINED: &[u8] = b"retained-original-origin";
const REPLACEMENT: &[u8] = b"retained-replacement-origin";
type Frame = [u8; MANAGED_ACTION_PREPARED_FRAME_BYTES];

pub(super) struct SelectedSlot {
	directory: File,
	segment: File,
	native: PreparedActionSlotSelection<'static>,
	pub(super) roles: [[u8; 32]; 2],
}

impl SelectedSlot {
	pub(super) fn new(sandbox: &mut Sandbox, profile: &File) -> TestResult<Self> {
		Self::new_named(sandbox, profile, SLOT)
	}

	fn new_named(sandbox: &mut Sandbox, profile: &File, name: &'static [u8]) -> TestResult<Self> {
		let directory = sandbox.mkdir(profile, name)?;
		let segment = sandbox.write_new(&directory, SEGMENT, &[])?;
		let extent = NonZeroUsize::new(MANAGED_ACTION_PREPARED_FRAME_BYTES).unwrap();
		let native = PreparedActionSlotSelection {
			name: UnixComponent::new(name)?,
			directory: expected(&directory)?,
			segment: expected(&segment)?,
			ordinary_mount: mount_id(&directory, StatxFlags::MNT_ID)?,
			unique_mount: mount_id(&directory, MOUNT_ID_UNIQUE)?,
			extent,
			limit: extent,
		};
		let (boot, mount_ns, user_ns) = kernel_location()?;
		let mut slot = Vec::from(boot);
		for namespace in [mount_ns, user_ns] {
			slot.extend(makedev(namespace.major, namespace.minor).to_le_bytes());
			slot.extend(namespace.inode.get().to_le_bytes());
		}
		for mount in [native.ordinary_mount, native.unique_mount] {
			slot.extend(mount.get().to_le_bytes());
		}
		slot.extend(geteuid().as_raw().to_le_bytes());
		slot.extend(getegid().as_raw().to_le_bytes());
		for file in [profile, &directory] {
			let metadata = file.metadata()?;
			slot.extend(metadata.dev().to_le_bytes());
			slot.extend(metadata.ino().to_le_bytes());
		}
		slot.push(u8::try_from(name.len())?);
		slot.extend_from_slice(name);
		let slot_role = blake3::derive_key("ExaCopy Linux managed action slot identity v1", &slot);
		let metadata = segment.metadata()?;
		slot.extend(metadata.dev().to_le_bytes());
		slot.extend(metadata.ino().to_le_bytes());
		slot.extend_from_slice(SEGMENT);
		let segment_role =
			blake3::derive_key("ExaCopy Linux managed action segment identity v1", &slot);
		Ok(Self {
			directory,
			segment,
			native,
			roles: [slot_role, segment_role],
		})
	}

	pub(super) fn establish_origin(
		&self,
		review: &ApprovalReview,
		enrollment: &ApprovalEnrollment<'_>,
	) -> TestResult<ChainHead> {
		let (bytes, head) = origin(review, enrollment, enrollment.origin_ids[1])?;
		self.segment.write_all_at(&bytes, 0)?;
		self.segment.sync_all()?;
		self.directory.sync_all()?;
		Ok(head)
	}

	pub(super) fn exercise<'input>(
		&self,
		sandbox: &mut Sandbox,
		selection: &ApprovalSelection<'_>,
		input: impl Fn([u8; 32]) -> ApprovalInput<'input>,
		record: (&[u8], &[u8], &[u8], [u8; 32]),
		roots: CopyRoots<'_>,
		scratch: &mut [u8],
	) -> TestResult {
		let (grant, parent, activation, activation_digest) = record;
		let (host, host_digest) =
			exacopy_cli::assembly::linux::managed_sync::activation::encode_host_selection(
				selection,
			)?;
		assert_eq!(input(host_digest).host, host.as_slice());
		let now = || Some(selection.review.ids.observed_at);
		let make = |native, expected_host, expected_activation| PreparedApprovalInput {
			approval: input(expected_host),
			slot: native,
			grant,
			parent,
			activation,
			activation_digest: expected_activation,
		};
		let expected = exact(&self.segment)?;
		let original_profile = File::open(selection.profile.path)?;
		let original_parent = File::open(sandbox.path.join("live"))?;
		let arrival = with_scoped_prepared_recreate(
			selection,
			make(self.native, host_digest, activation_digest),
			roots,
			scratch,
			now,
			|held| {
				for (directory, mode) in [
					(&original_profile, FlockOperation::NonBlockingLockExclusive),
					(&original_parent, FlockOperation::NonBlockingLockShared),
					(&original_parent, FlockOperation::NonBlockingLockExclusive),
					(&self.directory, FlockOperation::NonBlockingLockShared),
					(&self.directory, FlockOperation::NonBlockingLockExclusive),
				] {
					assert_eq!(flock(directory, mode), Err(rustix::io::Errno::WOULDBLOCK));
				}
				assert_eq!(held.origin().head, selection.enrollment.prepared);
				assert_eq!(held.origin().extent, 432);
				assert_eq!(
					held.approval()
						.activation
						.as_ref()
						.map(|(_, digest)| *digest),
					Some(activation_digest),
				);
				Ok(held.origin())
			},
		)?;
		assert_eq!(arrival.head, selection.enrollment.prepared);
		assert_eq!(exact(&self.segment)?, expected);
		host_refusals::exercise(
			selection,
			&make(self.native, host_digest, activation_digest),
			roots,
			scratch,
		);
		edges::exercise_boundaries(
			selection,
			|| make(self.native, host_digest, activation_digest),
			roots,
			scratch,
			[&original_profile, &original_parent, &self.directory],
		)?;
		assert_eq!(exact(&self.segment)?, expected);
		let mut wrong_slot = self.native;
		wrong_slot.directory = wrong_slot.segment;
		let refused = |_: PreparedRecreate<'_>| -> Result<(), ApprovalError> {
			panic!("unselected prepared scope reached the callback")
		};
		assert!(matches!(
			with_scoped_prepared_recreate(
				selection,
				make(wrong_slot, host_digest, activation_digest),
				roots,
				scratch,
				now,
				refused,
			),
			Err(ApprovalError::Prepared(_))
		));
		for (host, activation) in [([0; 32], activation_digest), (host_digest, [0; 32])] {
			assert!(matches!(
				with_scoped_prepared_recreate(
					selection,
					make(self.native, host, activation),
					roots,
					scratch,
					now,
					refused,
				),
				Err(ApprovalError::Artifact)
			));
		}
		assert_eq!(exact(&self.segment)?, expected);

		let start = selection.review.ids.observed_at;
		let samples = [0, 1, 3, 2]
			.map(|delta| UnixTimestamp::new(start.seconds() + delta, start.nanoseconds()).unwrap());
		assert!(samples.into_iter().all(|sample| {
			let [start, end] = selection.enrollment.window;
			start <= sample && sample < end
		}));
		let sampled = Cell::new(0);
		let regressing = || {
			let index = sampled.get();
			sampled.set(index + 1);
			samples.get(index).copied()
		};
		assert!(matches!(
			with_scoped_prepared_recreate(
				selection,
				make(self.native, host_digest, activation_digest),
				roots,
				scratch,
				regressing,
				refused,
			),
			Err(ApprovalError::Time)
		));
		assert_eq!(sampled.get(), 4);
		assert_eq!(exact(&self.segment)?, expected);

		let (foreign, _) = origin(selection.review, selection.enrollment, [0x54; 16])?;
		self.segment.write_all_at(&foreign, 0)?;
		assert!(matches!(
			with_scoped_prepared_recreate(
				selection,
				make(self.native, host_digest, activation_digest),
				roots,
				scratch,
				now,
				refused,
			),
			Err(ApprovalError::Origin(_))
		));
		assert_eq!(exact(&self.segment)?, foreign);
		self.segment.write_all_at(&expected, 0)?;

		// Challenge postflight through the owned fixture, after admission.
		let mut replacement = None;
		let result = with_scoped_prepared_recreate(
			selection,
			make(self.native, host_digest, activation_digest),
			roots,
			scratch,
			now,
			|held| {
				assert_eq!(held.origin().head, selection.enrollment.prepared);
				sandbox
					.rename(&self.directory, SEGMENT, RETAINED)
					.expect("move the owned original origin inside the callback");
				replacement = Some(
					sandbox
						.write_new(&self.directory, SEGMENT, &expected)
						.expect("write a byte-identical owned replacement inside the callback"),
				);
				Ok(())
			},
		);
		let replacement = replacement.expect("the rebind callback was attended");
		assert!(matches!(
			result,
			Err(ApprovalError::Prepared(
				PreparedManagedActionError::Segment(SyncProfileStoreError::Changed)
			))
		));
		assert!(matches!(
			with_scoped_prepared_recreate(
				selection,
				make(self.native, host_digest, activation_digest),
				roots,
				scratch,
				now,
				refused,
			),
			Err(ApprovalError::Prepared(_))
		));
		assert_eq!(
			expected_identity(&open_child(&self.directory, RETAINED, OFlags::RDONLY)?)?,
			expected_identity(&self.segment)?
		);
		assert_eq!(
			expected_identity(&open_child(&self.directory, SEGMENT, OFlags::RDONLY)?)?,
			expected_identity(&replacement)?
		);
		assert_eq!(exact(&self.segment)?, expected);
		assert_ne!(
			expected_identity(&replacement)?,
			expected_identity(&self.segment)?
		);
		assert_eq!(exact(&replacement)?, expected);
		sandbox.rename(&self.directory, SEGMENT, REPLACEMENT)?;
		sandbox.rename(&self.directory, RETAINED, SEGMENT)?;

		let [source_name, peer_name] = match selection.review.from {
			SyncSide::Left => ROOT_NAMES,
			SyncSide::Right => [ROOT_NAMES[1], ROOT_NAMES[0]],
		};
		let source_root = open_child(
			&original_parent,
			source_name,
			OFlags::RDONLY | OFlags::DIRECTORY,
		)?;
		let peer = open_child(
			&original_parent,
			peer_name,
			OFlags::RDONLY | OFlags::DIRECTORY,
		)?;
		let source = open_child(&source_root, SUBJECT, OFlags::RDONLY)?;
		let source_identity = expected_identity(&source)?;
		let original_metadata = source.metadata()?;
		let source_mode = original_metadata.mode() & 0o777;
		assert_eq!(source_mode, 0o600);
		let original = read(&source_root, SUBJECT)?;
		assert_eq!(original, b"xyz");
		assert_missing(&peer, SUBJECT);
		let mut changed = false;
		let result = with_scoped_prepared_recreate(
			selection,
			make(self.native, host_digest, activation_digest),
			roots,
			scratch,
			now,
			|held| {
				assert_eq!(held.origin().head, selection.enrollment.prepared);
				// No namespace effect. Only the original owned source's mode changes.
				source
					.set_permissions(std::fs::Permissions::from_mode(0o400))
					.expect("change the fixture source mode inside the callback");
				changed = true;
				Ok(())
			},
		);
		assert!(changed, "the source mode callback was attended");
		let changed_mode = source.metadata()?.mode() & 0o777;
		// The original mode is restorable. The kernel change time is not.
		source.set_permissions(original_metadata.permissions())?;
		assert_eq!(changed_mode, 0o400);
		assert!(matches!(
			result,
			Err(ApprovalError::Scope(ManagedSyncPreviewError::Managed(
				ManagedSyncError::Preview(SyncPreviewError::Changed)
			)))
		));
		let named = open_child(&source_root, SUBJECT, OFlags::RDONLY)?;
		assert_eq!(expected_identity(&named)?, source_identity);
		assert_eq!(named.metadata()?.mode() & 0o777, source_mode);
		assert_eq!(read(&source_root, SUBJECT)?, original);
		assert_missing(&peer, SUBJECT);
		assert_missing(&peer, selection.enrollment.attempt.job_name.as_bytes());
		for (name, held) in [(SEGMENT, &self.segment), (REPLACEMENT, &replacement)] {
			let named = open_child(&self.directory, name, OFlags::RDONLY)?;
			assert_eq!(expected_identity(&named)?, expected_identity(held)?);
			assert_eq!(exact(&named)?, expected);
		}
		assert_missing(&self.directory, b"activation.claim");
		Ok(())
	}
}

fn origin(
	review: &ApprovalReview,
	enrollment: &ApprovalEnrollment<'_>,
	allocation: [u8; 16],
) -> TestResult<(Frame, ChainHead)> {
	let mut bytes = Vec::with_capacity(MANAGED_ACTION_PREPARED_FRAME_BYTES);
	let payload = encode_managed_action_prepared(&ManagedActionPrepared {
		enrollment: enrollment.origin_ids[0],
		allocation,
		profile: enrollment.ordinary_owner.0,
		pair: review.pair,
		predecessor_generation: 1,
		predecessor_root: enrollment.predecessor,
		review_parent: review.parent_digest,
		reviewed_action: review.action,
		child: ManagedActivationChild {
			public_plan: ApprovedPublicPlanDigest::from_bytes(review.child_digest),
			public_entry: PublicPlanEntryId::from_bytes(*review.ids.entry.as_bytes())?,
			private_plan: *enrollment.private_plan.as_bytes(),
			job: enrollment.attempt.job,
			entry: enrollment.attempt.entry,
			epoch: enrollment.attempt.epoch,
		},
		slot: enrollment.role_projections[0],
		segment: enrollment.role_projections[1],
	})?;
	let head = FrameWriter::new(&mut bytes, ChainHead::start())
		.append(FrameKind::ManagedActionPrepared, &payload)?;
	let frame = bytes
		.try_into()
		.map_err(|_| "unexpected origin frame extent")?;
	Ok((frame, head))
}

fn expected(file: &File) -> TestResult<ManagedSyncExpectedObject> {
	let (device, inode) = expected_identity(file)?;
	Ok(ManagedSyncExpectedObject {
		major: major(device),
		minor: minor(device),
		inode: std::num::NonZeroU64::new(inode).ok_or("zero fixture inode")?,
	})
}

fn expected_identity(file: &File) -> TestResult<(u64, u64)> {
	let metadata = file.metadata()?;
	Ok((metadata.dev(), metadata.ino()))
}

fn exact(file: &File) -> TestResult<Frame> {
	let mut bytes = [0; MANAGED_ACTION_PREPARED_FRAME_BYTES];
	file.read_exact_at(&mut bytes, 0)?;
	assert_eq!(
		file.read_at(&mut [0], MANAGED_ACTION_PREPARED_FRAME_BYTES as u64)?,
		0
	);
	Ok(bytes)
}
