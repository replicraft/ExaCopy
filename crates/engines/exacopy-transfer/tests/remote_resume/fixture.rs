use std::{
	cell::RefCell,
	future,
	num::{NonZeroU64, NonZeroUsize},
	rc::Rc,
};

use exacopy_endpoint::{ClosedStage, FreshStage, ReadView};
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{JournalEntryId, JournalEpoch, JournalJobId, OwnerDigest};
use exacopy_transfer::remote_capture::{
	CaptureCheckpoint, CaptureCheckpoints, CapturedReadAt, CheckpointStage, SourceEpoch,
};
use exacopy_transfer::remote_resume::{
	AllocatedCapture, AllocationBase, CaptureAttempt, RemoteScopeDigest, ReplayState,
	RestartAdmission, RestartJournal, RestartPlan, RestartRecord, RestartStage, ResumeHistory,
	ResumeScope, SyncedRestart, TargetState, plan_restart,
};

pub const OLD: u64 = 10;
pub const NEW: u64 = 11;
pub const CONTENT: &[u8] = b"abcdefgh";

pub fn epoch(value: u64) -> SourceEpoch {
	SourceEpoch::new(NonZeroU64::new(value).expect("nonzero fixture epoch"))
}

pub fn head(sequence: u64) -> ChainHead {
	ChainHead::after(sequence, [8; 32]).expect("valid fixture head")
}

pub fn history() -> ResumeHistory<u64> {
	ResumeHistory {
		scope: ResumeScope {
			job: JournalJobId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
				.expect("fixture job UUIDv7"),
			entry: JournalEntryId::from_bytes([2; 16]),
			owner: OwnerDigest::from_bytes([3; 32]),
			approved_scope: RemoteScopeDigest::from_bytes([4; 32]),
			maximum_length: 128,
		},
		allocation_base: AllocationBase::LegacyJobPrepared(head(1)),
		predecessor: head(11),
		previous: Some(CaptureAttempt {
			run: JournalEpoch::new(5),
			source: epoch(7),
			stage: OLD,
		}),
		previous_allocation: Some(AllocatedCapture {
			head: head(9),
			run: JournalEpoch::new(5),
			source: epoch(7),
		}),
		pending_allocation: AllocatedCapture {
			head: head(11),
			run: JournalEpoch::new(6),
			source: epoch(8),
		},
		pending_allocation_predecessor: head(10),
		state: ReplayState::CleanBeforeIntent,
	}
}

pub fn admission(scope: ResumeScope) -> RestartAdmission {
	RestartAdmission {
		scope,
		source: epoch(8),
		target: TargetState::Absent,
	}
}

pub fn plan() -> RestartPlan<u64> {
	let prior = history();
	plan_restart(prior, admission(prior.scope)).expect("authorized fixture")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
	Held,
	Restart,
	CheckSource,
	FinishSource,
	Read(u64),
	Write,
	Barrier,
	Checkpoint,
	Close,
	OpenReadBack,
	ReadBack,
	ClosedBinding,
}

#[derive(Clone, Copy, Default)]
pub enum Fault {
	#[default]
	None,
	PendingSource,
	FinishFailure,
	StaleSource,
	WrongBarrier,
	BarrierFailure,
	WrongClosedIdentity,
	CorruptReadBack,
	RestartBarrier,
	WrongRecord,
	WrongSequence,
	CheckpointBarrier,
}

pub type Tape = Rc<RefCell<Vec<Step>>>;
pub type Bytes = Rc<RefCell<Vec<u8>>>;

pub struct Source {
	data: &'static [u8],
	pub epoch: SourceEpoch,
	fault: Fault,
	tape: Tape,
}

impl CapturedReadAt for Source {
	type Error = &'static str;

	fn epoch(&self) -> SourceEpoch {
		self.epoch
	}
	fn length(&self) -> u64 {
		u64::try_from(self.data.len()).expect("fixture length")
	}
	fn max_window_bytes(&self) -> NonZeroUsize {
		NonZeroUsize::new(3).expect("fixture window")
	}

	async fn read_exact_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.tape.borrow_mut().push(Step::Read(offset));
		if matches!(self.fault, Fault::PendingSource) {
			future::pending::<()>().await;
		}
		let start = usize::try_from(offset).map_err(|_| "offset")?;
		bytes.copy_from_slice(&self.data[start..start + bytes.len()]);
		if matches!(self.fault, Fault::StaleSource) {
			self.epoch = epoch(12);
		}
		Ok(())
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		self.tape.borrow_mut().push(Step::CheckSource);
		Ok(())
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		self.tape.borrow_mut().push(Step::FinishSource);
		if matches!(self.fault, Fault::FinishFailure) {
			return Err("source finish");
		}
		Ok(())
	}
}

pub struct Stage {
	pub binding: u64,
	length: u64,
	bytes: Bytes,
	fault: Fault,
	tape: Tape,
}

impl FreshStage for Stage {
	type Error = &'static str;
	type Closed = Closed;
	const MAX_CHUNK_BYTES: usize = 5;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		self.bytes
			.borrow()
			.is_empty()
			.then_some(self.length)
			.ok_or("not fresh")
	}

	fn write_next(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
		self.tape.borrow_mut().push(Step::Write);
		self.bytes.borrow_mut().extend(bytes);
		Ok(())
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		self.tape.borrow_mut().push(Step::Close);
		let mut bytes = self.bytes.borrow().clone();
		if matches!(self.fault, Fault::CorruptReadBack) {
			bytes[0] ^= 1;
		}
		let binding = if matches!(self.fault, Fault::WrongClosedIdentity) {
			OLD
		} else {
			self.binding
		};
		Ok(Closed {
			binding,
			bytes,
			tape: self.tape,
		})
	}
}

impl CheckpointStage for Stage {
	type Binding = u64;

	fn sync_prefix(&mut self, _end: u64) -> Result<u64, Self::Error> {
		self.tape.borrow_mut().push(Step::Barrier);
		match self.fault {
			Fault::WrongBarrier => Ok(OLD),
			Fault::BarrierFailure => Err("stage barrier"),
			_ => Ok(self.binding),
		}
	}
}

impl RestartStage for Stage {
	fn held_binding(&self) -> Result<u64, Self::Error> {
		self.tape.borrow_mut().push(Step::Held);
		Ok(self.binding)
	}

	fn closed_binding(stage: &Closed) -> Result<u64, Self::Error> {
		stage.tape.borrow_mut().push(Step::ClosedBinding);
		Ok(stage.binding)
	}
}

#[derive(Debug)]
pub struct Closed {
	pub binding: u64,
	pub bytes: Vec<u8>,
	tape: Tape,
}

impl ClosedStage for Closed {
	type Error = &'static str;
	type Reader<'stage> = BackReader<'stage>;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.tape.borrow_mut().push(Step::OpenReadBack);
		Ok(BackReader(self))
	}
}

pub struct BackReader<'stage>(&'stage Closed);

impl ReadView for BackReader<'_> {
	type Error = &'static str;

	fn length(&self) -> u64 {
		u64::try_from(self.0.bytes.len()).expect("fixture extent")
	}
	fn recheck_observation(&self) -> Result<(), Self::Error> {
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.0.tape.borrow_mut().push(Step::ReadBack);
		let start = usize::try_from(offset).map_err(|_| "readback offset")?;
		bytes.copy_from_slice(&self.0.bytes[start..start + bytes.len()]);
		Ok(())
	}
}

pub struct Journal {
	pub head: ChainHead,
	pub records: Vec<RestartRecord<u64>>,
	pub checkpoints: Vec<(u64, CaptureCheckpoint)>,
	fault: Fault,
	tape: Tape,
}

impl CaptureCheckpoints<u64> for Journal {
	type Error = &'static str;

	fn record(&mut self, stage: u64, checkpoint: CaptureCheckpoint) -> Result<(), Self::Error> {
		self.tape.borrow_mut().push(Step::Checkpoint);
		self.checkpoints.push((stage, checkpoint));
		if matches!(self.fault, Fault::CheckpointBarrier) {
			return Err("checkpoint barrier");
		}
		Ok(())
	}
}

impl RestartJournal<u64> for Journal {
	fn sync_restart(
		&mut self,
		record: RestartRecord<u64>,
	) -> Result<SyncedRestart<u64>, Self::Error> {
		self.tape.borrow_mut().push(Step::Restart);
		if record.predecessor != self.head {
			return Err("changed predecessor");
		}
		self.records.push(record);
		if matches!(self.fault, Fault::RestartBarrier) {
			return Err("restart barrier");
		}
		self.head = head(self.head.sequence() + 1);
		let mut ack = SyncedRestart {
			record,
			head: self.head,
		};
		match self.fault {
			Fault::WrongRecord => ack.record.next.stage = OLD,
			Fault::WrongSequence => ack.head = head(self.head.sequence() + 1),
			_ => {}
		}
		Ok(ack)
	}
}

pub fn setup(data: &'static [u8], fault: Fault) -> (Source, Stage, Journal, Tape, Bytes) {
	let tape = Tape::default();
	let bytes = Bytes::default();
	let source = Source {
		data,
		epoch: epoch(8),
		fault,
		tape: Rc::clone(&tape),
	};
	let stage = Stage {
		binding: NEW,
		length: u64::try_from(data.len()).expect("fixture length"),
		bytes: Rc::clone(&bytes),
		fault,
		tape: Rc::clone(&tape),
	};
	let journal = Journal {
		head: history().predecessor,
		records: vec![],
		checkpoints: vec![],
		fault,
		tape: Rc::clone(&tape),
	};
	(source, stage, journal, tape, bytes)
}
