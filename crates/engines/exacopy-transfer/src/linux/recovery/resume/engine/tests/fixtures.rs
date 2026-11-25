use std::cell::{Cell, RefCell};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::linux_publication::PublicationFailure;
use exacopy_endpoint::linux_staging::ExtendedAttributes;
use exacopy_endpoint::{IoError, UnixComponent};
use exacopy_journal::frame::{ChainHead, Frame, FrameReader};
use exacopy_journal::{
	DestinationRootBinding, JournalEntryId, JournalJobId, RootCapabilityId, SourceTimes,
};
use exacopy_model::PublishNoClobber;

use super::*;
use crate::linux::{DestinationPlanBinding, PlanAttempt, SourcePlanBinding};

pub(super) const SOURCE: &[u8] = b"abcdef";
pub(super) const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(1, 14);
pub(super) const PLANNED_MODE: u32 = 0o640;
const SOURCE_ID: LinuxFileIdentity = LinuxFileIdentity::new(1, 11);
const DIRECTORY: LinuxFileIdentity = LinuxFileIdentity::new(1, 15);

type TestError = ResumeError<io::Error, io::Error, io::Error, io::Error>;

pub(super) struct Fixture {
	plan: LocalCopyPlan<'static>,
	pub(super) owner: OwnerDigest,
}

impl Fixture {
	pub(super) fn new() -> Self {
		let time = ObservedTimestamp::new(123, 45).unwrap();
		let component = |bytes| UnixComponent::new(bytes).unwrap();
		let plan = LocalCopyPlan::new(
			PlanAttempt {
				job: JournalJobId::from_bytes(uuid(1)).unwrap(),
				epoch: JournalEpoch::new(3),
				entry: JournalEntryId::from_bytes([2; 16]),
				job_name: component(b"job"),
				stage_name: component(b"stage"),
			},
			SourcePlanBinding {
				root_id: RootCapabilityId::from_bytes(uuid(3)).unwrap(),
				root_identity: LinuxFileIdentity::new(1, 10),
				file_identity: SOURCE_ID,
				length: SOURCE.len() as u64,
				modified_at: time,
				changed_at: time,
				component: component(b"source"),
			},
			DestinationPlanBinding {
				root: DestinationRootBinding {
					id: RootCapabilityId::from_bytes(uuid(4)).unwrap(),
					identity: LinuxFileIdentity::new(1, 13),
				},
				component: component(b"target"),
			},
		)
		.unwrap();
		Self {
			plan,
			owner: OwnerDigest::from_bytes([5; 32]),
		}
	}
}

pub(super) struct Simulation<'f>(pub(super) State, pub(super) JournalBoundary, &'f Fixture);

impl Simulation<'_> {
	pub(super) fn new<'f>(
		fixture: &'f Fixture,
		retained: &[u8],
		fail_journal: bool,
	) -> Simulation<'f> {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		let path = std::env::temp_dir().join(format!(
			"exacopy-resume-engine-{}-{}",
			std::process::id(),
			NEXT.fetch_add(1, Ordering::Relaxed),
		));
		fs::create_dir(&path).unwrap();
		let state = State {
			path,
			stage: RefCell::new(retained.to_vec()),
			writes: RefCell::new(Vec::new()),
			receipts: Cell::new(0),
			uncertain_publication: Cell::new(false),
			fail_journal,
		};
		let mut journal = DurableJournal::from_new_segment(TestSegment(
			File::create(state.path.join("journal")).unwrap(),
		))
		.unwrap();
		let _ = journal.append(FrameKind::JobPrepared, b"fixture").unwrap();
		let preparation = journal
			.append(FrameKind::EntryPrepared, b"fixture")
			.unwrap();
		drop(journal);
		let boundary = JournalBoundary {
			head: preparation.head(),
			offset: fs::metadata(state.path.join("journal")).unwrap().len(),
		};
		Simulation(state, boundary, fixture)
	}

	pub(super) fn resume(
		&self,
		mode: u32,
		ranges: &[CheckpointCandidate],
	) -> Result<(), TestError> {
		let plan = &self.2.plan;
		let time = plan.source().modified_at;
		let replay = JournalReplay {
			boundary: self.1,
			tail: JournalTail::Clean,
			source: Some(
				LiveSourceView::new(
					SOURCE_ID,
					plan.source().length,
					SourceTimes {
						accessed_at: time,
						modified_at: time,
						changed_at: time,
					},
				)
				.unwrap(),
			),
			source_link_count: Some(1),
			source_metadata: Some(
				SourceInodeMetadata::no_visible_extended_attributes(PLANNED_MODE, 0, 0, 1).unwrap(),
			),
			preparation_head: Some(self.1.head),
			stage: Some(STAGE),
			checkpoints: Vec::new(),
			sealed: None,
			verification: None,
			verification_head: None,
			metadata: None,
			metadata_head: None,
			intent: None,
			intent_head: None,
			observation: None,
			observation_head: None,
			durability: None,
			durability_head: None,
			latest_epoch: plan.context().epoch,
			last_effect_sequence: 0,
			recovery_stage_directory: None,
			published_recovery: false,
			receipt: None,
		};
		let mut scratch = [0; 2];
		let retained = Retained(&self.0);
		let resume = Resume::admit(
			Evidence {
				plan,
				replay: &replay,
				ranges,
				owner: self.2.owner,
			},
			&Source,
			RetainedStage {
				reader: &retained,
				identity: STAGE,
				mode,
			},
			scratch.len(),
			Ok,
		)?;
		resume.execute(&mut Directory(&self.0), &self.0, &mut scratch)
	}
}

pub(super) struct State {
	path: PathBuf,
	pub(super) stage: RefCell<Vec<u8>>,
	pub(super) writes: RefCell<Vec<(u64, usize)>>,
	pub(super) receipts: Cell<u8>,
	pub(super) uncertain_publication: Cell<bool>,
	fail_journal: bool,
}

impl State {
	pub(super) fn frames(&self) -> Vec<Frame> {
		let mut reader = FrameReader::new(
			File::open(self.path.join("journal")).unwrap(),
			ChainHead::start(),
		);
		std::iter::from_fn(|| reader.next_frame().unwrap()).collect()
	}

	fn latest(&self) -> FrameKind {
		self.frames().last().unwrap().kind()
	}
}

impl Drop for State {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.path);
	}
}

impl Records for State {
	type Error = io::Error;
	type Segment = TestSegment;

	fn resume_journal(
		&self,
		boundary: JournalBoundary,
	) -> Result<DurableJournal<Self::Segment>, Self::Error> {
		if self.fail_journal {
			return Err(io::Error::other("fixture refused the journal lease"));
		}
		let file = OpenOptions::new()
			.read(true)
			.write(true)
			.open(self.path.join("journal"))?;
		DurableJournal::resume_first_segment(TestSegment(file), boundary.head, boundary.offset)
			.map_err(io::Error::other)
	}

	fn sync_receipt(&self, _receipt: &CopyReceipt<'_>) -> Result<(), Self::Error> {
		assert_eq!(self.latest(), FrameKind::DurabilityRecorded);
		self.receipts.set(self.receipts.get() + 1);
		Ok(())
	}
}

struct Source;

#[derive(Clone, Copy)]
struct Metadata;

impl SourceMetadata for Metadata {
	type Timestamp = ObservedTimestamp;

	fn mode(self) -> u32 {
		PLANNED_MODE
	}

	fn accessed_at(self) -> Self::Timestamp {
		ObservedTimestamp::new(123, 45).unwrap()
	}
}

impl StagingSource for Source {
	type Identity = LinuxFileIdentity;
	type Metadata = Metadata;

	fn identity(&self) -> Self::Identity {
		SOURCE_ID
	}

	fn metadata(&self) -> Self::Metadata {
		Metadata
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, io::Error> {
		Ok(ExtendedAttributes::NoneVisible)
	}

	fn recheck_metadata(&self) -> Result<(), io::Error> {
		Ok(())
	}
}

impl ReadView for Source {
	type Error = io::Error;

	fn length(&self) -> u64 {
		SOURCE.len() as u64
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		read(SOURCE, offset, bytes);
		Ok(())
	}
}

struct Retained<'a>(&'a State);

impl ReadView for Retained<'_> {
	type Error = io::Error;

	fn length(&self) -> u64 {
		self.0.stage.borrow().len() as u64
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		read(&self.0.stage.borrow(), offset, bytes);
		Ok(())
	}
}

struct Directory<'a>(&'a State);

impl StageDirectory<Metadata, LinuxFileIdentity> for Directory<'_> {
	type Error = io::Error;
	type PublicationError = io::Error;
	type Reader<'stage>
		= Reader<'stage>
	where
		Self: 'stage;
	type Writer<'stage>
		= Writer<'stage>
	where
		Self: 'stage;

	fn identity(&self) -> LinuxFileIdentity {
		DIRECTORY
	}

	fn record_identity(identity: LinuxFileIdentity) -> LinuxFileIdentity {
		identity
	}

	fn open_writer(&mut self, _binding: CopyBinding) -> Result<Self::Writer<'_>, Self::Error> {
		assert_eq!(self.0.latest(), FrameKind::RecoveryStarted);
		Ok(Writer(self.0))
	}

	fn open_flushed_readback(
		&mut self,
		_binding: CopyBinding,
		_source: Metadata,
	) -> Result<Self::Reader<'_>, Self::Error> {
		assert_eq!(self.0.latest(), FrameKind::EntryPrepared);
		Ok(Reader(self.0))
	}
}

struct Writer<'a>(&'a State);

impl<'a> StageWriter for Writer<'a> {
	type Identity = LinuxFileIdentity;
	type Metadata = Metadata;
	type Error = io::Error;
	type Reader = Reader<'a>;

	fn identity(&self) -> Self::Identity {
		STAGE
	}

	fn check_ownership(&self, _metadata: Self::Metadata) -> Result<(), Self::Error> {
		Ok(())
	}

	fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Self::Error> {
		self.0.writes.borrow_mut().push((offset, bytes.len()));
		let offset = usize::try_from(offset).unwrap();
		let end = offset + bytes.len();
		let mut stage = self.0.stage.borrow_mut();
		if end > stage.len() {
			stage.resize(end, 0);
		}
		stage[offset..end].copy_from_slice(bytes);
		Ok(())
	}

	fn set_len(&mut self, length: u64) -> Result<(), Self::Error> {
		self.0
			.stage
			.borrow_mut()
			.resize(usize::try_from(length).unwrap(), 0);
		Ok(())
	}

	fn flush(&mut self) -> Result<(), Self::Error> {
		Ok(())
	}

	fn close_writes(self) -> Result<Self::Reader, Self::Error> {
		Ok(Reader(self.0))
	}
}

struct Reader<'a>(&'a State);

impl StageReader for Reader<'_> {
	type Identity = LinuxFileIdentity;
	type Metadata = Metadata;
	type Error = io::Error;

	fn identity(&self) -> Self::Identity {
		STAGE
	}

	fn length(&self) -> u64 {
		self.0.stage.borrow().len() as u64
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), IoError> {
		read(&self.0.stage.borrow(), offset, bytes);
		Ok(())
	}

	fn apply_metadata_with_access_time(
		self,
		_metadata: Metadata,
		time: ObservedTimestamp,
	) -> Result<Self, Self::Error> {
		assert_eq!(self.0.latest(), FrameKind::RecoveryStarted);
		assert_eq!(time, Metadata.accessed_at());
		Ok(self)
	}

	fn sync_stage_directory(&self) -> Result<(), Self::Error> {
		Ok(())
	}
}

impl ExclusivePublication for Reader<'_> {
	type Error = io::Error;

	fn publish_no_clobber(
		self,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<Self::Error>> {
		assert_eq!(self.0.latest(), FrameKind::PublishIntent);
		assert_eq!(
			authorization.binding(),
			CopyBinding::new(
				JobId::try_from_bytes(uuid(1)).unwrap(),
				EntryId::new(1),
				RunEpoch::new(4),
				StageId::from_bytes([2; 16]),
			),
		);
		assert_eq!(&*self.0.stage.borrow(), SOURCE);
		if self.0.uncertain_publication.get() {
			return Err(PublicationFailure::Uncertain(io::Error::other(
				"fixture lost the publication outcome",
			)));
		}
		Ok(())
	}
}

fn read(stream: &[u8], offset: u64, bytes: &mut [u8]) {
	let offset = usize::try_from(offset).unwrap();
	bytes.copy_from_slice(&stream[offset..offset + bytes.len()]);
}

fn uuid(marker: u8) -> [u8; 16] {
	let mut bytes = [marker; 16];
	bytes[6] = 0x70;
	bytes[8] = 0x80;
	bytes
}

pub(super) struct TestSegment(File);

impl Read for TestSegment {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.0.read(bytes)
	}
}

impl Seek for TestSegment {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.0.seek(position)
	}
}

impl Write for TestSegment {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0.write(bytes)
	}
	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl JournalSegment for TestSegment {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		let metadata = self.0.metadata()?;
		Ok(metadata.is_file().then_some(metadata.len()))
	}

	fn sync(&self) -> io::Result<()> {
		self.0.sync_all()
	}
}
