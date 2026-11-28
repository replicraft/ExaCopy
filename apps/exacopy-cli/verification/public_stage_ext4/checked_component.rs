//! Foreground checked transfer component controls under fixture-only authority.

use std::cell::{Cell, RefCell};
use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use exacopy_endpoint::linux_apply::{
	ApplyRecord, ApplyRole, ApplyStep, LocalApplyAdmission, NativeRenameFacts, PublishedFacts,
};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{
	ApplyCrashProfile, ApplyProcessCrashEnvironment, ApplyQualification, ApplyQualificationDigest,
	DurableJournalError, LOCAL_RECEIPT_LOCATION, LinuxFileIdentity, MAX_OWNER_BYTES, OwnerDigest,
	OwnerTimestamp, PublicApplyIntent, PublicApplyOwnerRecord, ReceiptCommitted,
};
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
use exacopy_platform::linux::{DestinationRoot, observe_remote_destination};
use exacopy_transfer::linux::{
	CheckedApplyAuthority, CheckedApplyError, CheckedApplyFence, CheckedCopyError,
	MAX_LOCAL_COPY_PLAN_BYTES, MAX_PUBLIC_APPLY_RECEIPT_BYTES, PublicApplyIntentObservation,
	PublicApplyIntentSelection, PublicApplyReceipt, PublicApplyStageRequest,
	apply_checked_public_plan,
};
use exacopy_transfer::public_plan::admit_single_file_plan;
use rustix::fs::{self as native_fs, Mode, OFlags};

use super::fixture::{APPROVED, Fixture, INCUMBENT, SOURCE, TARGET, attempt, buffer, component};
use super::plan_new_file;

const SEGMENT_CAP: usize = 16 * 1024;
const REFUSAL: &str = "fixture denied receipt commit";

#[derive(Clone, Copy, Eq, PartialEq)]
enum Case {
	Complete,
	RefuseReceiptCommit,
}

// This test adapter supplies observations to the generic engine. It has no
// qualified SDK enrollment or live grant and cannot be called outside tests.
struct FixtureAuthority<'root> {
	root: &'root DestinationRoot,
	stage: &'root Path,
	receipt: &'root Path,
	segment: &'root Path,
	selection: PublicApplyIntentSelection,
	now: OwnerTimestamp,
	binding: CopyBinding,
	case: Case,
	job_creates: Cell<u8>,
	owner: Cell<Option<OwnerDigest>>,
	stage_identity: Cell<Option<LinuxFileIdentity>>,
	fence: Cell<Option<CheckedApplyFence>>,
	rename: Cell<Option<PublishedFacts>>,
	settled: Cell<bool>,
	artifacts_at_commit: RefCell<Option<CommitArtifacts>>,
}

struct CommitArtifacts {
	receipt: Snapshot,
	segment: Snapshot,
}

struct Snapshot {
	identity: JobFileIdentity,
	bytes: Vec<u8>,
}

impl LocalApplyAdmission for FixtureAuthority<'_> {
	type Guard<'gate>
		= ()
	where
		Self: 'gate;

	fn enter(&self, step: ApplyStep) -> io::Result<Self::Guard<'_>> {
		match step {
			ApplyStep::Create(ApplyRole::Job) => {
				assert_eq!(self.job_creates.replace(1), 0);
			}
			ApplyStep::Append(ApplyRecord::ReceiptCommit) => {
				assert!(self.settled.get());
				let original = CommitArtifacts {
					receipt: snapshot(self.receipt, MAX_PUBLIC_APPLY_RECEIPT_BYTES),
					segment: snapshot(self.segment, SEGMENT_CAP),
				};
				assert!(self.artifacts_at_commit.replace(Some(original)).is_none());
				if self.case == Case::RefuseReceiptCommit {
					return Err(io::Error::new(io::ErrorKind::PermissionDenied, REFUSAL));
				}
			}
			_ => {}
		}
		Ok(())
	}
}

impl CheckedApplyAuthority for FixtureAuthority<'_> {
	type Error = io::Error;

	fn observe(&self) -> io::Result<PublicApplyIntentObservation> {
		let current = environment(self.root)?;
		assert_eq!(current, self.selection.qualification.environment);
		Ok(PublicApplyIntentObservation {
			now: self.now,
			profile: self.selection.qualification.profile,
			environment: current,
		})
	}

	fn bind_owner(&self, owner: OwnerDigest) -> io::Result<()> {
		assert_eq!(self.job_creates.get(), 1);
		assert_eq!(self.owner.replace(Some(owner)), None);
		Ok(())
	}

	fn bind_stage(&self, binding: CopyBinding, stage: LinuxFileIdentity) -> io::Result<()> {
		assert_eq!(binding, self.binding);
		let named = regular_identity(self.stage);
		assert_eq!(stage, LinuxFileIdentity::new(named.device, named.inode));
		assert_eq!(self.stage_identity.replace(Some(stage)), None);
		Ok(())
	}

	fn bind_intent(&self, fence: CheckedApplyFence) -> io::Result<()> {
		assert_eq!(fence.binding(), self.binding);
		assert_eq!(Some(fence.owner()), self.owner.get());
		assert!(self.stage_identity.get().is_some());
		assert_eq!(self.fence.replace(Some(fence)), None);
		Ok(())
	}

	fn enter_rename(
		&self,
		fence: CheckedApplyFence,
		facts: NativeRenameFacts<'_>,
	) -> io::Result<Self::Guard<'_>> {
		assert_eq!(Some(fence), self.fence.get());
		assert_eq!(facts.binding, self.binding);
		assert_eq!(facts.target, component(TARGET));
		assert_eq!(
			facts.destination,
			JobFileIdentity::from(self.root.identity())
		);
		assert_eq!(facts.stage, regular_identity(self.stage));
		assert_eq!(
			facts.stage_directory,
			identity(self.stage.parent().unwrap(), true)
		);
		assert_eq!(
			self.rename.replace(Some(PublishedFacts {
				target: facts.stage,
				stage_directory: facts.stage_directory,
				destination: facts.destination,
			})),
			None
		);
		Ok(())
	}

	fn bind_settled(&self, observed: PublishedFacts) -> io::Result<()> {
		assert_eq!(Some(observed), self.rename.get());
		assert!(!self.settled.replace(true));
		Ok(())
	}
}

fn environment(root: &DestinationRoot) -> io::Result<ApplyProcessCrashEnvironment> {
	let facts = observe_remote_destination(root).map_err(io::Error::other)?;
	let ids = facts.ids();
	Ok(ApplyProcessCrashEnvironment {
		boot_id: ids.boot_id,
		mount_namespace: ids.mount_namespace,
		unique_mount: ids.unique_mount,
		device: ids.root.device,
	})
}

pub(super) fn exercise() {
	for case in [Case::Complete, Case::RefuseReceiptCommit] {
		let fixture = Fixture::new();
		exercise_case(&fixture, case);
		fixture.finish();
	}
}

fn exercise_case(fixture: &Fixture, case: Case) {
	let (source, destination) = fixture.open_roots();
	let roots = Fixture::roots(&source, &destination);
	let source_path = fixture.source();
	let source_identity = regular_identity(&source_path);
	let incumbent = fixture.target().with_file_name("unselected-incumbent");
	let mut held_incumbent = File::create_new(&incumbent).unwrap();
	held_incumbent.write_all(INCUMBENT).unwrap();
	drop(held_incumbent);
	let incumbent_identity = regular_identity(&incumbent);
	absent(&fixture.target());

	let (bundle, selected_plan) = Fixture::plan(roots);
	let approved = admit_single_file_plan(
		bundle.canonical_body(),
		bundle.canonical_page(),
		selected_plan,
	)
	.unwrap();
	let attempt = attempt("component-checked-apply", 19);
	let private = plan_new_file(roots, attempt, component(SOURCE), component(TARGET)).unwrap();
	let profile = fixture.profile();
	let binding = Fixture::binding(&approved, attempt);
	let request = PublicApplyStageRequest {
		approved: &approved,
		private_plan: &private,
		binding,
		profile,
	};
	let actual_environment = environment(&destination).unwrap();
	assert_eq!(actual_environment.device, source.identity().device());
	let selection = PublicApplyIntentSelection {
		approved_plan: binding.public_plan,
		qualification: ApplyQualification {
			record: ApplyQualificationDigest::from_bytes([0x51; 32]),
			// Wire enum for the component input. The host is not the enrolled Arm64 profile.
			profile: ApplyCrashProfile::Arm64UbuntuExt4FixtureV1,
			environment: actual_environment,
		},
	};
	let stage_path = fixture.stage(attempt);
	let receipt_path = fixture.job(attempt).join(LOCAL_RECEIPT_LOCATION);
	let segment_path = fixture.journal(attempt);
	let authority = FixtureAuthority {
		root: &destination,
		stage: &stage_path,
		receipt: &receipt_path,
		segment: &segment_path,
		selection,
		now: profile.created,
		binding: CopyBinding::new(
			JobId::try_from_bytes(*attempt.job.as_bytes()).unwrap(),
			EntryId::new(1),
			RunEpoch::new(attempt.epoch.get()),
			StageId::from_bytes(*attempt.entry.as_bytes()),
		),
		case,
		job_creates: Cell::new(0),
		owner: Cell::new(None),
		stage_identity: Cell::new(None),
		fence: Cell::new(None),
		rename: Cell::new(None),
		settled: Cell::new(false),
		artifacts_at_commit: RefCell::new(None),
	};
	let result = apply_checked_public_plan(roots, request, selection, &authority, &mut buffer());
	assert_eq!(authority.job_creates.get(), 1);
	assert!(authority.settled.get());
	let original = authority.artifacts_at_commit.borrow_mut().take().unwrap();
	let terminal = match case {
		Case::Complete => Some(result.unwrap()),
		Case::RefuseReceiptCommit => {
			assert!(matches!(
				result,
				Err(CheckedApplyError::Published(CheckedCopyError::Journal(
					FrameKind::ReceiptCommitted,
					DurableJournalError::Admission(cause)
				))) if cause.kind() == io::ErrorKind::PermissionDenied
					&& cause.to_string() == REFUSAL
			));
			None
		}
	};

	let target = fixture.target();
	assert_eq!(
		regular_identity(&target),
		authority.rename.get().unwrap().target
	);
	assert_eq!(snapshot(&target, APPROVED.len()).bytes, APPROVED);
	absent(&stage_path);
	assert_eq!(regular_identity(&source_path), source_identity);
	assert_eq!(snapshot(&source_path, APPROVED.len()).bytes, APPROVED);
	assert_eq!(regular_identity(&incumbent), incumbent_identity);
	assert_eq!(snapshot(&incumbent, INCUMBENT.len()).bytes, INCUMBENT);

	let job = fixture.job(attempt);
	let signed = snapshot(&job.join("owner.cbor"), MAX_OWNER_BYTES).bytes;
	let owner =
		PublicApplyOwnerRecord::decode(&signed, profile.id, &profile.signer.verifying_key())
			.unwrap();
	assert_eq!(Some(owner.digest()), authority.owner.get());
	assert_eq!(owner.manifest().binding, binding);
	assert_eq!(
		snapshot(&job.join("plan.cbor"), MAX_LOCAL_COPY_PLAN_BYTES).bytes,
		private.encode()
	);
	let artifact = snapshot(&receipt_path, MAX_PUBLIC_APPLY_RECEIPT_BYTES);
	assert_eq!(artifact.identity, original.receipt.identity);
	assert_eq!(artifact.bytes, original.receipt.bytes);
	let receipt = PublicApplyReceipt::decode(&artifact.bytes).unwrap();
	assert_eq!(receipt.qualification(), selection.qualification.record);
	let journal = snapshot(&segment_path, SEGMENT_CAP);
	assert_eq!(journal.identity, original.segment.identity);
	let mut frames = FrameReader::new(journal.bytes.as_slice(), ChainHead::start());
	let intent = authority.fence.get().unwrap().head();
	let mut seen_intent = false;
	let mut seen_committed = false;
	let mut final_kind = None;
	while let Some(frame) = frames.next_frame().unwrap() {
		final_kind = Some(frame.kind());
		match frame.kind() {
			FrameKind::PublishIntent => {
				assert!(!seen_intent);
				assert_eq!(frame.head(), intent);
				assert!(
					receipt.matches_intent(intent, &PublicApplyIntent::from_frame(&frame).unwrap())
				);
				seen_intent = true;
			}
			FrameKind::ReceiptCommitted => {
				assert!(!seen_committed);
				let record = ReceiptCommitted::from_frame(&frame).unwrap();
				assert_eq!(record.digest(), receipt.digest());
				assert_eq!(record.durability(), receipt.private().durability_frame());
				seen_committed = true;
			}
			_ => {}
		}
	}
	assert!(seen_intent);
	assert_eq!(frames.offset(), u64::try_from(journal.bytes.len()).unwrap());
	if let Some(terminal) = terminal {
		let tail = journal
			.bytes
			.strip_prefix(original.segment.bytes.as_slice())
			.unwrap();
		let mut frame = FrameReader::new(tail, receipt.private().durability_frame());
		assert_eq!(
			frame.next_frame().unwrap().unwrap().head(),
			terminal.terminal
		);
		assert!(frame.next_frame().unwrap().is_none());
		assert!(seen_committed);
		assert_eq!(final_kind, Some(FrameKind::ReceiptCommitted));
		assert_eq!(frames.head(), terminal.terminal);
		assert_eq!(terminal.receipt, receipt);
		assert_eq!(terminal.receipt.encode(), artifact.bytes);
	} else {
		assert_eq!(journal.bytes, original.segment.bytes);
		assert!(!seen_committed);
		assert_eq!(final_kind, Some(FrameKind::DurabilityRecorded));
		assert_eq!(frames.head(), receipt.private().durability_frame());
	}
}

// Reads the exact current extent through the same no-follow file and checks
// the name around the read. These files belong to the cooperating fixture.
fn snapshot(path: &Path, cap: usize) -> Snapshot {
	let identity = regular_identity(path);
	let mut file = File::from(
		native_fs::open(
			path,
			OFlags::RDONLY
				| OFlags::CLOEXEC
				| OFlags::NOFOLLOW
				| OFlags::NONBLOCK
				| OFlags::NOATIME,
			Mode::empty(),
		)
		.unwrap(),
	);
	let metadata = file.metadata().unwrap();
	assert!(metadata.is_file());
	assert_eq!(
		(metadata.dev(), metadata.ino()),
		(identity.device, identity.inode)
	);
	let length = usize::try_from(metadata.len()).unwrap();
	assert!((1..=cap).contains(&length));
	let mut bytes = vec![0; length];
	file.read_exact(&mut bytes).unwrap();
	assert_eq!(file.read(&mut [0]).unwrap(), 0);
	assert_eq!(file.metadata().unwrap().len(), metadata.len());
	assert_eq!(regular_identity(path), identity);
	Snapshot { identity, bytes }
}

fn regular_identity(path: &Path) -> JobFileIdentity {
	identity(path, false)
}

fn identity(path: &Path, directory: bool) -> JobFileIdentity {
	let metadata = fs::symlink_metadata(path).unwrap();
	if directory {
		assert!(metadata.is_dir());
	} else {
		assert!(metadata.is_file());
	}
	JobFileIdentity {
		device: metadata.dev(),
		inode: metadata.ino(),
	}
}

fn absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path).unwrap_err().kind(),
		io::ErrorKind::NotFound
	);
}
