use std::cell::RefCell;
use std::future::{Future, pending};
use std::num::{NonZeroU64, NonZeroUsize};
use std::task::{Context, Poll, Waker};

use exacopy_endpoint::{ClosedStage, FreshStage, ReadView};

mod admission;

use super::{
	CaptureCheckpoint, CaptureCheckpoints, CaptureError, CapturedReadAt, CheckpointStage,
	SourceEpoch, StageStep, capture, capture_live,
};

const CONTENT: &[u8] = b"abcdefg";
const STAGE: u8 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
	ObserveSource,
	FinishSource,
	Read(u64, usize),
	Write(usize),
	Sync(u64),
	Checkpoint(u64),
	Close,
	Open,
	ReadBack(u64, usize),
	ObserveReadBack,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Fault {
	#[default]
	None,
	FailRead,
	StaleRead,
	PendingRead,
	CheckpointBarrier,
	CheckpointRecord,
	Close,
	ReadBackDigest,
	FinalSource,
}

#[derive(Debug, Default)]
struct Trace {
	bytes: Vec<u8>,
	events: Vec<Event>,
	ranges: Vec<CaptureCheckpoint>,
	barrier: Option<u64>,
}

type State = RefCell<Trace>;

struct Source<'test> {
	state: &'test State,
	bytes: &'test [u8],
	epoch: SourceEpoch,
	fault: Fault,
}

impl CapturedReadAt for Source<'_> {
	type Error = &'static str;

	fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	fn length(&self) -> u64 {
		u64::try_from(self.bytes.len()).unwrap()
	}

	fn max_window_bytes(&self) -> NonZeroUsize {
		NonZeroUsize::new(2).unwrap()
	}

	async fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Self::Error> {
		self.state
			.borrow_mut()
			.events
			.push(Event::Read(offset, out.len()));
		if offset != 0 {
			match self.fault {
				Fault::FailRead => return Err("short read"),
				Fault::StaleRead => self.epoch = epoch(2),
				Fault::PendingRead => pending::<()>().await,
				_ => {}
			}
		}
		let start = usize::try_from(offset).unwrap();
		out.copy_from_slice(&self.bytes[start..start + out.len()]);
		Ok(())
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		self.state.borrow_mut().events.push(Event::ObserveSource);
		Ok(())
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		self.state.borrow_mut().events.push(Event::FinishSource);
		if self.fault == Fault::FinalSource {
			return Err("EOF changed");
		}
		Ok(())
	}
}

#[derive(Debug)]
struct Writer<'test> {
	state: &'test State,
	length: u64,
	fault: Fault,
}

impl<'test> FreshStage for Writer<'test> {
	type Error = &'static str;
	type Closed = Reader<'test>;

	const MAX_CHUNK_BYTES: usize = 3;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		assert!(self.state.borrow().bytes.is_empty());
		Ok(self.length)
	}

	fn write_next(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
		assert!(!bytes.is_empty() && bytes.len() <= Self::MAX_CHUNK_BYTES);
		let mut state = self.state.borrow_mut();
		state.events.push(Event::Write(bytes.len()));
		state.bytes.extend_from_slice(bytes);
		state.barrier = None;
		Ok(())
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		self.state.borrow_mut().events.push(Event::Close);
		if self.fault == Fault::Close {
			return Err("close");
		}
		let mut bytes = self.state.borrow().bytes.clone();
		assert_eq!(u64::try_from(bytes.len()).unwrap(), self.length);
		if self.fault == Fault::ReadBackDigest {
			bytes[0] ^= 1;
		}
		Ok(Reader {
			state: self.state,
			bytes,
		})
	}
}

impl CheckpointStage for Writer<'_> {
	type Binding = u8;

	fn sync_prefix(&mut self, end: u64) -> Result<Self::Binding, Self::Error> {
		let mut state = self.state.borrow_mut();
		state.events.push(Event::Sync(end));
		assert_eq!(u64::try_from(state.bytes.len()).unwrap(), end);
		if self.fault == Fault::CheckpointBarrier {
			return Err("barrier");
		}
		state.barrier = Some(end);
		Ok(STAGE)
	}
}

#[derive(Clone, Debug)]
struct Reader<'test> {
	state: &'test State,
	bytes: Vec<u8>,
}

impl ClosedStage for Reader<'_> {
	type Error = &'static str;
	type Reader<'stage>
		= Self
	where
		Self: 'stage;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.state.borrow_mut().events.push(Event::Open);
		Ok(self.clone())
	}
}

impl ReadView for Reader<'_> {
	type Error = &'static str;

	fn length(&self) -> u64 {
		u64::try_from(self.bytes.len()).unwrap()
	}

	fn read_exact_at(&self, offset: u64, out: &mut [u8]) -> Result<(), Self::Error> {
		assert!(out.len() <= Writer::MAX_CHUNK_BYTES);
		self.state
			.borrow_mut()
			.events
			.push(Event::ReadBack(offset, out.len()));
		let start = usize::try_from(offset).unwrap();
		out.copy_from_slice(&self.bytes[start..start + out.len()]);
		Ok(())
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.state.borrow_mut().events.push(Event::ObserveReadBack);
		Ok(())
	}
}

struct Checkpoints<'test> {
	state: &'test State,
	fault: Fault,
}

impl CaptureCheckpoints<u8> for Checkpoints<'_> {
	type Error = &'static str;

	fn record(&mut self, stage: u8, range: CaptureCheckpoint) -> Result<(), Self::Error> {
		assert_eq!(stage, STAGE);
		let mut state = self.state.borrow_mut();
		let end = range.offset.checked_add(range.length).unwrap();
		assert_eq!(state.barrier, Some(end));
		state.events.push(Event::Checkpoint(range.offset));
		if self.fault == Fault::CheckpointRecord {
			return Err("record");
		}
		state.ranges.push(range);
		Ok(())
	}
}

fn epoch(id: u64) -> SourceEpoch {
	SourceEpoch::new(NonZeroU64::new(id).unwrap())
}

fn fixture<'test>(
	state: &'test State,
	bytes: &'test [u8],
	fault: Fault,
) -> (Source<'test>, Writer<'test>, Checkpoints<'test>) {
	(
		Source {
			state,
			bytes,
			epoch: epoch(1),
			fault,
		},
		Writer {
			state,
			length: u64::try_from(bytes.len()).unwrap(),
			fault,
		},
		Checkpoints { state, fault },
	)
}

fn complete<F: Future>(future: F) -> F::Output {
	let mut future = std::pin::pin!(future);
	match future
		.as_mut()
		.poll(&mut Context::from_waker(Waker::noop()))
	{
		Poll::Ready(result) => result,
		Poll::Pending => panic!("fixture paused unexpectedly"),
	}
}

#[test]
fn writes_bounded_windows_and_records_digests_only_after_prefix_barriers() {
	let state = State::default();
	let (mut source, writer, mut records) = fixture(&state, CONTENT, Fault::None);
	let captured = complete(capture(
		&mut source,
		epoch(1),
		writer,
		&mut records,
		&mut [0; 4],
		NonZeroU64::new(3).unwrap(),
	))
	.unwrap();
	let (_, evidence) = captured.into_parts();
	assert_eq!(evidence.epoch, epoch(1));
	assert_eq!(evidence.length, 7);
	assert_eq!(&evidence.source_digest, blake3::hash(CONTENT).as_bytes());
	assert_eq!(evidence.stage_digest.as_bytes(), &evidence.source_digest);
	let state = state.borrow();
	assert_eq!(state.bytes, CONTENT);
	assert_eq!(
		state.events,
		[
			Event::ObserveSource,
			Event::Read(0, 2),
			Event::Write(2),
			Event::Read(2, 1),
			Event::Write(1),
			Event::Sync(3),
			Event::Checkpoint(0),
			Event::Read(3, 2),
			Event::Write(2),
			Event::Read(5, 1),
			Event::Write(1),
			Event::Sync(6),
			Event::Checkpoint(3),
			Event::Read(6, 1),
			Event::Write(1),
			Event::Sync(7),
			Event::Checkpoint(6),
			Event::Close,
			Event::Open,
			Event::ReadBack(0, 3),
			Event::ReadBack(3, 3),
			Event::ReadBack(6, 1),
			Event::ObserveReadBack,
			Event::FinishSource,
		]
	);
	for (range, (offset, bytes)) in
		state
			.ranges
			.iter()
			.zip([(0, &b"abc"[..]), (3, &b"def"[..]), (6, &b"g"[..])])
	{
		assert_eq!(range.epoch, epoch(1));
		assert_eq!(range.offset, offset);
		assert_eq!(range.length, u64::try_from(bytes.len()).unwrap());
		assert_eq!(&range.digest, blake3::hash(bytes).as_bytes());
	}
	assert_eq!(state.ranges.len(), 3);
}

#[test]
fn empty_stream_still_requires_private_read_back_and_terminal_source_close() {
	let state = State::default();
	let (mut source, writer, mut records) = fixture(&state, b"", Fault::None);
	let capture = complete(capture_live(
		&mut source,
		epoch(1),
		writer,
		&mut records,
		&mut [],
	))
	.unwrap();
	let (_, evidence) = capture.into_parts();
	assert_eq!(evidence.source_digest, *blake3::hash(b"").as_bytes());
	assert_eq!(
		state.borrow().events,
		[
			Event::ObserveSource,
			Event::Close,
			Event::Open,
			Event::ObserveReadBack,
			Event::FinishSource,
		]
	);
}

#[test]
fn stale_or_incomplete_read_cannot_write_a_second_window() {
	for fault in [Fault::StaleRead, Fault::FailRead] {
		let state = State::default();
		let (mut source, writer, mut records) = fixture(&state, CONTENT, fault);
		let result = complete(capture_live(
			&mut source,
			epoch(1),
			writer,
			&mut records,
			&mut [0; 4],
		));
		match fault {
			Fault::StaleRead => assert!(
				matches!(result, Err(CaptureError::Epoch { expected, found }) if expected == epoch(1) && found == epoch(2))
			),
			Fault::FailRead => assert!(matches!(result, Err(CaptureError::Read { offset: 2, .. }))),
			_ => unreachable!(),
		}
		let trace = state.borrow();
		assert_eq!(trace.bytes, b"ab");
		assert!(trace.ranges.is_empty());
		assert!(!trace.events.contains(&Event::Close));
	}
}

#[test]
fn ambiguous_prefix_barrier_or_record_failure_stops_before_another_read() {
	for fault in [Fault::CheckpointBarrier, Fault::CheckpointRecord] {
		let state = State::default();
		let (mut source, writer, mut records) = fixture(&state, CONTENT, fault);
		let result = complete(capture(
			&mut source,
			epoch(1),
			writer,
			&mut records,
			&mut [0; 4],
			NonZeroU64::new(3).unwrap(),
		));
		match fault {
			Fault::CheckpointBarrier => assert!(matches!(
				result,
				Err(CaptureError::Stage {
					step: StageStep::SyncPrefix { end: 3 },
					..
				})
			)),
			Fault::CheckpointRecord => assert!(matches!(
				result,
				Err(CaptureError::Checkpoint { offset: 0, .. })
			)),
			_ => unreachable!(),
		}
		let trace = state.borrow();
		assert_eq!(trace.bytes, b"abc");
		assert!(trace.ranges.is_empty());
		assert_eq!(
			trace.events.contains(&Event::Checkpoint(0)),
			fault == Fault::CheckpointRecord
		);
		assert!(!trace.events.contains(&Event::Read(3, 2)));
		assert!(!trace.events.contains(&Event::Close));
	}
}

#[test]
fn final_close_readback_and_source_recheck_each_gate_the_result() {
	for fault in [Fault::Close, Fault::ReadBackDigest, Fault::FinalSource] {
		let state = State::default();
		let (mut source, writer, mut records) = fixture(&state, CONTENT, fault);
		let result = complete(capture_live(
			&mut source,
			epoch(1),
			writer,
			&mut records,
			&mut [0; 4],
		));
		match fault {
			Fault::Close => assert!(matches!(
				result,
				Err(CaptureError::Stage {
					step: StageStep::Close,
					..
				})
			)),
			Fault::ReadBackDigest => assert!(matches!(result, Err(CaptureError::DigestMismatch))),
			Fault::FinalSource => assert!(matches!(
				result,
				Err(CaptureError::SourceFinish("EOF changed"))
			)),
			_ => unreachable!(),
		}
		assert_eq!(state.borrow().ranges.len(), 1);
		match fault {
			Fault::Close => assert!(!state.borrow().events.contains(&Event::Open)),
			Fault::ReadBackDigest => {
				assert_eq!(state.borrow().events.last(), Some(&Event::ObserveReadBack))
			}
			Fault::FinalSource => {
				assert_eq!(state.borrow().events.last(), Some(&Event::FinishSource))
			}
			_ => unreachable!(),
		}
	}
}

#[test]
fn dropping_pending_capture_leaves_only_the_confirmed_private_prefix() {
	let state = State::default();
	let (mut source, writer, mut records) = fixture(&state, CONTENT, Fault::PendingRead);
	{
		let mut scratch = [0; 4];
		let mut future = std::pin::pin!(capture(
			&mut source,
			epoch(1),
			writer,
			&mut records,
			&mut scratch,
			NonZeroU64::new(2).unwrap(),
		));
		assert!(
			future
				.as_mut()
				.poll(&mut Context::from_waker(Waker::noop()))
				.is_pending()
		);
	}
	let state = state.borrow();
	assert_eq!(state.bytes, b"ab");
	assert_eq!(state.ranges.len(), 1);
	assert_eq!(state.events.last(), Some(&Event::Read(2, 2)));
	assert!(!state.events.contains(&Event::Close));
}
