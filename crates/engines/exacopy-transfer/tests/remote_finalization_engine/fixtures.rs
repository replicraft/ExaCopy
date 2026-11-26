use std::cell::{Cell, RefCell};
use std::future;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::linux_publication::PublicationFailure;
use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_endpoint::{
	ClosedStage, FreshStage, JournalFileBarrier, JournalSegment, ReadView, UnixComponent,
};
use exacopy_journal::frame::{ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind};
use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationReplay;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadBody as Body, RemoteDownloadContext,
	RemoteDownloadDestination, RemoteDownloadDurability, RemoteDownloadOwner,
	RemoteDownloadOwnerRecord, RemoteDownloadRecord, RemoteDownloadRoute, RemoteDownloadScope,
	RemoteDownloadSource, RemoteEpochs, RemoteSourceObservation,
};
use exacopy_journal::{
	DurableJournal, JournalEntryId, JournalJobId, LinuxFileIdentity, OwnerProfileId,
	OwnerTimestamp, OwnerToken, RootCapabilityId, StreamLength, SyncedFrame,
};
use exacopy_model::{CopyBinding, EntryId, JobId, PublishNoClobber, RunEpoch, StageId};
use exacopy_transfer::remote_capture::{
	CaptureCheckpoint, CaptureCheckpoints, CapturedReadAt, CheckpointStage, ObservedCapture,
	SourceEpoch, capture_live,
};
use exacopy_transfer::remote_finalization::{
	CurrentRemoteAuthority, RemoteAuthorityCheck, RemoteFinalizationJournal,
	RemoteFinalizationRequest, RemoteFinalizationResult, RemoteFinalizationStage,
	RemotePublicationAuthority, RemotePublicationFacts, RemotePublicationFence, RemoteReadyStage,
	RemoteReadyStageFacts, RemoteStageLocation, RemoteStageNames, finalize_capture,
};
use exacopy_transfer::remote_metadata::{RemoteMetadataSelection, admit_sftp_metadata};
use exacopy_transfer::remote_resume::TargetState;

#[path = "fixtures/receipt.rs"]
mod receipt;
#[path = "fixtures/setup.rs"]
mod setup;

use receipt::Receipts;
use setup::selected_replay;
pub use setup::{RETIRED_STAGE, ReplayBeforeFinalization, TestRun};

pub const PARENT: LinuxFileIdentity = LinuxFileIdentity::new(7, 9);
pub const DIRECTORY: LinuxFileIdentity = LinuxFileIdentity::new(7, 12);
pub const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(7, 13);
const JOB: [u8; 16] = [1, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const NONCE: [u8; 16] = [53; 16];
const GRANT: [u8; 32] = [21; 32];
const QUALIFICATION: [u8; 32] = [22; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
	Location,
	Metadata,
	StageCheck(u8),
	Authority(u8),
	Append(FrameKind),
	NativeFence,
	Publish,
	ReceiptJob(u8),
	ReceiptDirectory,
	ReceiptFile,
	ReceiptWrite,
	ReceiptFileSync,
	ReceiptDirectorySync,
	JobDirectorySync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
	None,
	Boundary,
	Grant(u8),
	Qualification(u8),
	Target(u8, TargetState),
	StageMismatch,
	WrongNames,
	WrongStage,
	WrongDirectory,
	WrongParent,
	WrongStageName,
	ChangedReadyNames,
	NativeFence,
	Stop(Step),
	Ack(FrameKind),
	WrongBarrier(FrameKind),
	Offset(FrameKind),
	Conflict,
	Uncertain,
	WrongPublishedIdentity,
}

pub type Tape = Rc<RefCell<Vec<Step>>>;
pub type Bytes = Rc<RefCell<Cursor<Vec<u8>>>>;

fn enter(tape: &Tape, fault: Fault, step: Step) -> Result<(), &'static str> {
	tape.borrow_mut().push(step);
	if fault == Fault::Stop(step) {
		Err("injected boundary")
	} else {
		Ok(())
	}
}

#[derive(Clone)]
struct MemorySegment<const DARWIN: bool>(Bytes);

impl<const DARWIN: bool> Read for MemorySegment<DARWIN> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		self.0.borrow_mut().read(buffer)
	}
}
impl<const DARWIN: bool> Write for MemorySegment<DARWIN> {
	fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
		self.0.borrow_mut().write(buffer)
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}
impl<const DARWIN: bool> Seek for MemorySegment<DARWIN> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.0.borrow_mut().seek(position)
	}
}
impl<const DARWIN: bool> JournalSegment for MemorySegment<DARWIN> {
	const BARRIER: JournalFileBarrier = if DARWIN {
		JournalFileBarrier::DarwinFullFsync
	} else {
		JournalFileBarrier::SyncAll
	};
	fn regular_length(&self) -> io::Result<Option<u64>> {
		Ok(Some(
			u64::try_from(self.0.borrow().get_ref().len()).unwrap(),
		))
	}
	fn sync(&self) -> io::Result<()> {
		Ok(())
	}
}

pub struct Journal {
	writer: DurableJournal<MemorySegment<false>>,
	bytes: Bytes,
	boundary: RemoteReplayBoundary,
	fault: Fault,
	tape: Tape,
}

impl Journal {
	fn write_entry(&mut self, kind: FrameKind, payload: Vec<u8>) -> (Frame, SyncedFrame) {
		let stride = u64::try_from(payload.len() + FRAME_OVERHEAD_BYTES).unwrap();
		let pair = self.writer.append_frame(kind, payload).unwrap();
		self.boundary.head = pair.0.head();
		self.boundary.offset += stride;
		pair
	}

	fn prefix(&mut self, context: RemoteDownloadContext, body: Body<'_>) -> Frame {
		let prior = self.boundary.head;
		let record = RemoteDownloadRecord::new(
			context,
			(prior != ChainHead::start()).then_some(prior),
			body,
		)
		.unwrap();
		self.write_entry(body.kind(), record.encode().unwrap()).0
	}
}

impl RemoteFinalizationJournal for Journal {
	type Error = &'static str;
	fn boundary(&mut self) -> Result<RemoteReplayBoundary, Self::Error> {
		let mut current = self.boundary;
		if self.fault == Fault::Boundary {
			current.offset += 1;
		}
		Ok(current)
	}
	fn append(
		&mut self,
		expected: RemoteReplayBoundary,
		kind: FrameKind,
		mut payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), Self::Error> {
		assert_eq!(expected, self.boundary);
		enter(&self.tape, self.fault, Step::Append(kind))?;
		if self.fault == Fault::Ack(kind) {
			payload.push(0);
		}
		let foreign_barrier = if self.fault == Fault::WrongBarrier(kind) {
			let copy = Rc::new(RefCell::new(Cursor::new(
				self.bytes.borrow().get_ref().clone(),
			)));
			let mut journal = DurableJournal::resume_first_segment(
				MemorySegment::<true>(copy),
				expected.head,
				expected.offset,
			)
			.unwrap();
			Some(journal.append_frame(kind, payload.clone()).unwrap().1)
		} else {
			None
		};
		let (frame, synced) = self.write_entry(kind, payload);
		if self.fault == Fault::Offset(kind) {
			self.boundary.offset += 1;
		}
		Ok((frame, foreign_barrier.unwrap_or(synced)))
	}
}

struct Checkpoints<'journal> {
	journal: &'journal mut Journal,
	context: RemoteDownloadContext,
	prepared: ChainHead,
	epochs: RemoteEpochs,
}

impl CaptureCheckpoints<LinuxFileIdentity> for Checkpoints<'_> {
	type Error = &'static str;
	fn record(
		&mut self,
		stage: LinuxFileIdentity,
		range: CaptureCheckpoint,
	) -> Result<(), Self::Error> {
		assert_eq!(stage, STAGE);
		assert_eq!(range.epoch.get(), self.epochs.source.get());
		self.journal.prefix(
			self.context,
			Body::RangeCheckpoint {
				prepared: self.prepared,
				epochs: self.epochs,
				ordinal: 1,
				offset: range.offset,
				length: range.length,
				digest: exacopy_journal::StreamDigest::from_bytes(range.digest),
			},
		);
		Ok(())
	}
}

struct Source(&'static [u8], SourceEpoch);

impl CapturedReadAt for Source {
	type Error = &'static str;
	fn epoch(&self) -> SourceEpoch {
		self.1
	}
	fn length(&self) -> u64 {
		u64::try_from(self.0.len()).unwrap()
	}
	fn max_window_bytes(&self) -> NonZeroUsize {
		NonZeroUsize::new(64).unwrap()
	}
	fn read_exact_at(
		&mut self,
		offset: u64,
		output: &mut [u8],
	) -> impl Future<Output = Result<(), Self::Error>> {
		read(self.0, offset, output);
		future::ready(Ok(()))
	}
	fn recheck(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
		future::ready(Ok(()))
	}
	fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
		future::ready(Ok(()))
	}
}

fn read(data: &[u8], offset: u64, output: &mut [u8]) {
	let start = usize::try_from(offset).unwrap();
	output.copy_from_slice(&data[start..start + output.len()]);
}

struct Stage(Vec<u8>, RemoteReadyStageFacts, Fault, Tape);

impl FreshStage for Stage {
	type Error = &'static str;
	type Closed = Closed;
	const MAX_CHUNK_BYTES: usize = 64;
	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		Ok(self.1.length)
	}
	fn write_next(&mut self, input: &[u8]) -> Result<(), Self::Error> {
		self.0.extend_from_slice(input);
		Ok(())
	}
	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		Ok(Closed(self.0, self.1, self.2, self.3))
	}
}

impl CheckpointStage for Stage {
	type Binding = LinuxFileIdentity;
	fn sync_prefix(&mut self, end: u64) -> Result<Self::Binding, Self::Error> {
		assert_eq!(usize::try_from(end).unwrap(), self.0.len());
		Ok(STAGE)
	}
}

pub struct Closed(Vec<u8>, RemoteReadyStageFacts, Fault, Tape);

pub struct Independent<'a>(&'a [u8]);

impl ReadView for Independent<'_> {
	type Error = &'static str;
	fn length(&self) -> u64 {
		u64::try_from(self.0.len()).unwrap()
	}
	fn recheck_observation(&self) -> Result<(), Self::Error> {
		Ok(())
	}
	fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), Self::Error> {
		read(self.0, offset, output);
		Ok(())
	}
}

impl ClosedStage for Closed {
	type Error = &'static str;
	type Reader<'a> = Independent<'a>;
	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		Ok(Independent(&self.0))
	}
}

pub struct Ready(RemoteReadyStageFacts, Fault, Tape, Cell<u8>);

impl RemoteFinalizationStage for Closed {
	type Error = &'static str;
	type Ready = Ready;
	fn inspect_location(&self) -> Result<RemoteStageLocation<'_>, Self::Error> {
		enter(&self.3, self.2, Step::Location)?;
		let mut location = RemoteStageLocation {
			binding: self.1.binding,
			stage: self.1.stage,
			directory: self.1.directory,
			parent: self.1.parent,
			names: names(self.2 == Fault::WrongNames),
		};
		match self.2 {
			Fault::WrongStage => location.stage = LinuxFileIdentity::new(8, 13),
			Fault::WrongDirectory => location.directory = LinuxFileIdentity::new(7, 14),
			Fault::WrongParent => location.parent = LinuxFileIdentity::new(7, 15),
			Fault::WrongStageName => {
				location.names.stage = UnixComponent::new(b"other-part").unwrap()
			}
			_ => {}
		}
		Ok(location)
	}

	fn prepare_metadata(self, length: u64) -> Result<Self::Ready, Self::Error> {
		enter(&self.3, self.2, Step::Metadata)?;
		assert_eq!(length, u64::try_from(self.0.len()).unwrap());
		Ok(Ready(self.1, self.2, self.3, Cell::new(0)))
	}
}

impl RemoteReadyStage for Ready {
	type Error = &'static str;

	fn names(&self) -> RemoteStageNames<'_> {
		names(matches!(
			self.1,
			Fault::WrongNames | Fault::ChangedReadyNames
		))
	}

	fn recheck(&self) -> Result<RemoteReadyStageFacts, Self::Error> {
		let calls = self.3.get() + 1;
		self.3.set(calls);
		enter(&self.2, self.1, Step::StageCheck(calls))?;
		let mut facts = self.0;
		if self.1 == Fault::StageMismatch {
			facts.mode = 0o644;
		}
		Ok(facts)
	}
	fn publish(
		self,
		permit: PublishNoClobber,
		fence: RemotePublicationFence,
	) -> Result<RemotePublicationFacts, PublicationFailure<Self::Error>> {
		assert_eq!(permit.binding(), self.0.binding);
		assert_eq!(fence.context().job.as_bytes(), &JOB);
		assert_eq!(fence.authority().grant, GRANT);
		assert_eq!(fence.authority().qualification, QUALIFICATION);
		assert!(fence.intent().sequence() > 0);
		self.2.borrow_mut().push(Step::NativeFence);
		if self.1 == Fault::NativeFence {
			return Err(PublicationFailure::Uncertain("native grant fence refused"));
		}
		self.2.borrow_mut().push(Step::Publish);
		match self.1 {
			Fault::Conflict => Err(PublicationFailure::Conflict("incumbent")),
			Fault::Uncertain => Err(PublicationFailure::Uncertain("unconfirmed")),
			_ => Ok(RemotePublicationFacts {
				target: if self.1 == Fault::WrongPublishedIdentity {
					PARENT
				} else {
					STAGE
				},
				directory: DIRECTORY,
				parent: PARENT,
			}),
		}
	}
}

fn names(wrong_target: bool) -> RemoteStageNames<'static> {
	let target: &[u8] = if wrong_target { b"wrong" } else { b"target" };
	RemoteStageNames {
		stage: UnixComponent::new(b"part").unwrap(),
		target: UnixComponent::new(target).unwrap(),
	}
}

pub struct Authority(pub RemotePublicationAuthority, Fault, Tape, u8);

impl RemoteAuthorityCheck for Authority {
	type Error = &'static str;
	fn recheck(&mut self) -> Result<CurrentRemoteAuthority, Self::Error> {
		self.3 += 1;
		enter(&self.2, self.1, Step::Authority(self.3))?;
		let mut binding = self.0;
		let mut target = TargetState::Absent;
		match self.1 {
			Fault::Grant(call) if call == self.3 => binding.grant = [99; 32],
			Fault::Qualification(call) if call == self.3 => binding.qualification = [98; 32],
			Fault::Target(call, state) if call == self.3 => target = state,
			_ => {}
		}
		Ok(CurrentRemoteAuthority { binding, target })
	}
}

pub fn verify_committed_receipt<'owner>(
	owner: &'owner RemoteDownloadOwnerRecord,
	journal: &[u8],
	receipt: &[u8],
) -> RemoteFinalizationReplay<'owner> {
	use exacopy_journal::remote_download::finalization_replay::{
		RemoteFinalizationPhase, RemoteReceiptAssociation,
	};
	let replay = selected_replay(owner, journal, QUALIFICATION, Some(receipt));
	assert!(replay.issue().is_none());
	assert_eq!(replay.phase(), RemoteFinalizationPhase::ReceiptCommitted);
	assert_eq!(
		replay.receipt_association(),
		RemoteReceiptAssociation::Matched
	);
	assert!(replay.validated_receipt().unwrap().is_some());
	replay
}
