use std::fs::{self, File};
use std::io::{ErrorKind, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader};
use exacopy_journal::{
	DurabilityRecorded, EntryPrepared, JobPrepared, LOCAL_RECEIPT_LOCATION, LinuxFileIdentity,
	MetadataRecorded, OwnerRecord, PublicationOutcome, PublishIntent, PublishObserved,
	ReceiptCommitted, ReceiptDigest, StageSealed, VerificationRecorded,
};
use rustix::fs::{Mode, OFlags, open};

use super::{
	Checkpoint, Fixture, SOURCE, STAGE_FILE, TARGET, component, fixture_signer, profile_id,
};
use exacopy_transfer::linux::{CopyReceipt, LocalCopyPlan};

pub(super) const STAGE_DIRECTORY: &str = "stage";
pub(super) const SEGMENT: &str = "journal/00000000000000000001.exajnl";
const PLAN: &str = "plan.cbor";
const OWNER: &str = "owner.cbor";
pub(super) const SUCCESS_ORDER: &[FrameKind] = &[
	FrameKind::JobPrepared,
	FrameKind::EntryPrepared,
	FrameKind::StageSealed,
	FrameKind::VerificationRecorded,
	FrameKind::MetadataRecorded,
	FrameKind::PublishIntent,
	FrameKind::PublishObserved,
	FrameKind::DurabilityRecorded,
	FrameKind::ReceiptCommitted,
];

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
	pub(super) identity: LinuxFileIdentity,
	bytes: Vec<u8>,
	mode: u32,
	uid: u32,
	gid: u32,
	links: u64,
	modified: (i64, i64),
	changed: (i64, i64),
}

impl Snapshot {
	pub(super) fn read(path: &Path) -> Self {
		// A normal read could change the sealed stage's atime before the child resumes.
		let file = open(
			path,
			OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NOATIME,
			Mode::empty(),
		)
		.unwrap_or_else(|error| panic!("inspect fixture artifact {path:?}: {error}"));
		let mut file = File::from(file);
		let stat = file.metadata().expect("stat the held fixture artifact");
		assert!(stat.is_file(), "fixture artifact {path:?} is not regular");
		let mut bytes = Vec::new();
		file.read_to_end(&mut bytes)
			.expect("read the held fixture artifact");
		Self {
			identity: LinuxFileIdentity::new(stat.dev(), stat.ino()),
			bytes,
			mode: stat.mode(),
			uid: stat.uid(),
			gid: stat.gid(),
			links: stat.nlink(),
			modified: (stat.mtime(), stat.mtime_nsec()),
			changed: (stat.ctime(), stat.ctime_nsec()),
		}
	}

	pub(super) fn assert_copied_from(&self, source: &Self) {
		assert_ne!(self.identity, source.identity, "copy aliases its source");
		assert_eq!(self.bytes, source.bytes, "copy has different bytes");
		assert_eq!(self.mode, source.mode, "copy has different mode");
		assert_eq!(
			(self.uid, self.gid),
			(source.uid, source.gid),
			"copy has different ownership"
		);
		assert_eq!(self.modified, source.modified, "copy has different mtime");
		assert_eq!(self.links, 1, "copy unexpectedly has another name");
	}
}

pub(super) fn assert_crash(fixture: &Fixture, checkpoint: Checkpoint, source: &Snapshot) {
	let stage_directory = fixture.job().join(STAGE_DIRECTORY);
	let stage = stage_directory.join(STAGE_FILE);
	let target = fixture.destination().join(TARGET);
	let receipt_path = fixture.job().join(LOCAL_RECEIPT_LOCATION);
	let last_kind = match checkpoint {
		Checkpoint::PlanSynced => FrameKind::JobPrepared,
		Checkpoint::StageSealed => FrameKind::MetadataRecorded,
		Checkpoint::IntentSynced | Checkpoint::RenamedAndSynced => FrameKind::PublishIntent,
		Checkpoint::ReceiptSynced => FrameKind::DurabilityRecorded,
		Checkpoint::ReceiptCommitted => FrameKind::ReceiptCommitted,
		_ => panic!("unexpected normal copy checkpoint {checkpoint:?}"),
	};
	let journal = Journal::read(fixture, last_kind);
	let plan_bytes =
		fs::read(fixture.job().join(PLAN)).expect("read canonical plan after the kill");
	let plan = LocalCopyPlan::decode(&plan_bytes).expect("decode the surviving plan");
	journal.assert_preparation(fixture, &plan, source);

	let published = match checkpoint {
		Checkpoint::PlanSynced => {
			assert_absent(&stage_directory);
			assert_absent(&target);
			assert_absent(&receipt_path);
			return;
		}
		Checkpoint::StageSealed | Checkpoint::IntentSynced => {
			assert_absent(&target);
			Snapshot::read(&stage)
		}
		Checkpoint::RenamedAndSynced | Checkpoint::ReceiptSynced | Checkpoint::ReceiptCommitted => {
			assert_absent(&stage);
			Snapshot::read(&target)
		}
		_ => panic!("unexpected normal copy checkpoint {checkpoint:?}"),
	};
	published.assert_copied_from(source);
	journal.assert_seal(&plan, source, &published);

	if checkpoint == Checkpoint::StageSealed {
		assert_absent(&receipt_path);
		return;
	}
	let intent = journal.assert_intent(&plan, published.identity);
	if matches!(
		checkpoint,
		Checkpoint::IntentSynced | Checkpoint::RenamedAndSynced
	) {
		assert_absent(&receipt_path);
		return;
	}
	journal.assert_receipt(fixture, &plan, &published, &intent);
}

pub(super) fn assert_conflict(fixture: &Fixture, stage: &Snapshot, incumbent: &Snapshot) {
	assert_eq!(
		Snapshot::read(&fixture.job().join(STAGE_DIRECTORY).join(STAGE_FILE)),
		*stage,
		"exclusive rename must preserve the staged object"
	);
	assert_eq!(
		Snapshot::read(&fixture.destination().join(TARGET)),
		*incumbent,
		"exclusive rename must preserve the incumbent object"
	);
	assert_ne!(
		stage.identity, incumbent.identity,
		"incumbent aliases stage"
	);
	assert_absent(&fixture.job().join(LOCAL_RECEIPT_LOCATION));
	let journal = Journal::read(fixture, FrameKind::PublishObserved);
	let intent_frame = journal.frame(FrameKind::PublishIntent);
	let intent = PublishIntent::from_frame(intent_frame).expect("decode intent after conflict");
	assert_eq!(
		intent.target.stage, stage.identity,
		"intent identifies the stage"
	);
	let observed = PublishObserved::from_frame(journal.frame(FrameKind::PublishObserved))
		.expect("decode the surviving failure observation");
	observed
		.validate_intent(intent_frame)
		.expect("failure belongs to this intent");
	assert!(
		!matches!(observed.outcome(), PublicationOutcome::Published { .. }),
		"conflict cannot be observed as publication"
	);
}

struct Journal(Vec<Frame>);

impl Journal {
	fn read(fixture: &Fixture, last_kind: FrameKind) -> Self {
		let last = SUCCESS_ORDER
			.iter()
			.position(|kind| *kind == last_kind)
			.expect("stop after a normal copy frame");
		Self(read_frames(fixture, &SUCCESS_ORDER[..=last]))
	}

	fn frame(&self, kind: FrameKind) -> &Frame {
		self.0
			.iter()
			.find(|frame| frame.kind() == kind)
			.unwrap_or_else(|| panic!("missing surviving frame {kind:?}"))
	}

	fn assert_preparation(&self, fixture: &Fixture, plan: &LocalCopyPlan<'_>, source: &Snapshot) {
		let owner_bytes = fs::read(fixture.job().join(OWNER)).expect("reopen signed owner record");
		let owner = OwnerRecord::decode(
			&owner_bytes,
			profile_id(),
			&fixture_signer().verifying_key(),
		)
		.expect("authenticate the surviving owner");
		let prepared = JobPrepared::from_frame(self.frame(FrameKind::JobPrepared))
			.expect("decode the surviving job preparation");
		assert_eq!(
			owner.manifest().plan_digest,
			plan.digest(),
			"owner plan binding"
		);
		assert_eq!(prepared.owner_digest, owner.digest(), "job owner binding");
		assert_eq!(prepared.context, plan.context(), "job plan binding");
		assert_eq!(
			prepared.destination_root,
			plan.destination().root,
			"destination binding"
		);
		assert_eq!(
			plan.source().file_identity,
			source.identity,
			"source binding"
		);
		assert_eq!(
			plan.source().component,
			component(SOURCE),
			"source name binding"
		);
		assert_eq!(
			plan.destination().component,
			component(TARGET),
			"target name binding"
		);
	}

	fn assert_seal(&self, plan: &LocalCopyPlan<'_>, source: &Snapshot, copy: &Snapshot) {
		let entry = EntryPrepared::from_frame(self.frame(FrameKind::EntryPrepared))
			.expect("decode the surviving entry preparation");
		let sealed = StageSealed::from_frame(self.frame(FrameKind::StageSealed))
			.expect("decode the surviving stage seal");
		assert_eq!(
			entry.preparation().stage,
			copy.identity,
			"prepared stage binding"
		);
		assert_eq!(sealed.context, plan.context(), "seal plan binding");
		assert_eq!(sealed.stage, copy.identity, "sealed stage binding");
		let verification =
			VerificationRecorded::from_frame(self.frame(FrameKind::VerificationRecorded))
				.expect("decode the surviving read-back verification");
		let metadata = MetadataRecorded::from_frame(self.frame(FrameKind::MetadataRecorded))
			.expect("decode the surviving metadata observation");
		assert_eq!(
			verification.source().identity,
			source.identity,
			"verified source binding"
		);
		assert_eq!(
			verification.stage().identity,
			copy.identity,
			"verified stage binding"
		);
		assert_eq!(
			verification.stage().digest.as_bytes(),
			blake3::hash(&copy.bytes).as_bytes()
		);
		assert_eq!(metadata.stage, copy.identity, "metadata stage binding");
		assert_eq!(
			metadata.metadata.mode(),
			copy.mode & 0o7777,
			"recorded file permissions"
		);
	}

	fn assert_intent(
		&self,
		plan: &LocalCopyPlan<'_>,
		copy: LinuxFileIdentity,
	) -> PublishIntent<'_> {
		let intent = PublishIntent::from_frame(self.frame(FrameKind::PublishIntent))
			.expect("decode surviving publication intent");
		let verification =
			VerificationRecorded::from_frame(self.frame(FrameKind::VerificationRecorded))
				.expect("decode the intent's read-back verification");
		assert_eq!(intent.target.stage, copy, "intent stage binding");
		assert_eq!(
			intent.target.parent,
			plan.destination().root.identity,
			"intent parent binding"
		);
		assert_eq!(
			intent.target.component,
			component(TARGET),
			"intent target name"
		);
		assert_eq!(
			intent.context.plan_digest,
			plan.digest(),
			"intent plan binding"
		);
		assert_eq!(
			intent.target.verification_digest,
			verification.record_digest()
		);
		intent
	}

	fn assert_receipt(
		&self,
		fixture: &Fixture,
		plan: &LocalCopyPlan<'_>,
		copy: &Snapshot,
		intent: &PublishIntent<'_>,
	) {
		let observed_frame = self.frame(FrameKind::PublishObserved);
		let observed = PublishObserved::from_frame(observed_frame)
			.expect("decode surviving successful publication observation");
		assert_eq!(
			observed.outcome(),
			PublicationOutcome::Published {
				target: copy.identity
			},
			"observation identifies the actual published inode"
		);
		let durability_frame = self.frame(FrameKind::DurabilityRecorded);
		let durability = DurabilityRecorded::from_frame(durability_frame)
			.expect("decode surviving directory barrier observation");
		durability
			.validate_evidence(
				self.frame(FrameKind::MetadataRecorded),
				self.frame(FrameKind::PublishIntent),
				observed_frame,
			)
			.expect("bind the barrier observation to the published object");
		let stage_directory = fs::symlink_metadata(fixture.job().join(STAGE_DIRECTORY))
			.expect("inspect original stage parent after successful publication");
		assert_eq!(
			durability.barriers().stage_directory,
			LinuxFileIdentity::new(stage_directory.dev(), stage_directory.ino()),
			"directory barriers bind the original stage parent"
		);
		let artifact = fs::read(fixture.job().join(LOCAL_RECEIPT_LOCATION))
			.expect("reopen synchronized receipt bytes");
		let receipt = CopyReceipt::decode(&artifact).expect("decode synchronized receipt bytes");
		assert_eq!(
			receipt.durability_frame(),
			durability_frame.head(),
			"receipt barrier binding"
		);
		assert_eq!(
			receipt.evidence().context,
			plan.context(),
			"receipt plan binding"
		);
		assert_eq!(
			receipt.evidence().target,
			intent.target.component,
			"receipt target binding"
		);
		assert_eq!(
			receipt.evidence().stream.identity,
			copy.identity,
			"receipt published inode"
		);
		if let Some(commit_frame) = self
			.0
			.last()
			.filter(|frame| frame.kind() == FrameKind::ReceiptCommitted)
		{
			let commit =
				ReceiptCommitted::from_frame(commit_frame).expect("decode receipt commitment");
			let mut digest = blake3::Hasher::new();
			digest.update(b"ExaCopy/linux-copy-receipt/v1\0");
			digest.update(&artifact);
			commit
				.validate_evidence(
					durability_frame,
					ReceiptDigest::from_bytes(*digest.finalize().as_bytes()),
				)
				.expect("bind the final commitment to the exact on-disk artifact");
		}
	}
}

pub(super) fn read_frames(fixture: &Fixture, order: &[FrameKind]) -> Vec<Frame> {
	let file = File::open(fixture.job().join(SEGMENT)).expect("reopen raw first journal segment");
	let length = file.metadata().expect("stat reopened first segment").len();
	let mut reader = FrameReader::new(file, ChainHead::start());
	let mut frames = Vec::new();
	for &expected in order {
		let frame = reader
			.next_frame()
			.expect("read the journal through a clean frame boundary")
			.expect("find the expected surviving frame");
		assert_eq!(frame.kind(), expected, "unexpected surviving journal frame");
		assert_eq!(
			frame.head().sequence(),
			u64::try_from(frames.len()).expect("frame count fits u64") + 1,
			"journal sequence must be contiguous"
		);
		frames.push(frame);
	}
	assert!(
		reader
			.next_frame()
			.expect("read clean journal EOF")
			.is_none(),
		"journal contains a frame after the stopped boundary {:?}",
		order.last()
	);
	assert_eq!(reader.offset(), length, "read the entire journal segment");
	frames
}

pub(super) fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path)
			.expect_err("fixture name must be absent")
			.kind(),
		ErrorKind::NotFound,
		"unexpected namespace observation at {path:?}"
	);
}
