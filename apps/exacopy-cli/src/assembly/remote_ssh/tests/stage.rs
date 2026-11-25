use std::cell::RefCell;
use std::io;

use exacopy_endpoint::{ClosedStage, FreshStage, ReadView};
use exacopy_transfer::remote_capture::{CaptureCheckpoint, CaptureCheckpoints, CheckpointStage};

#[derive(Debug, Default)]
pub(super) struct Trace(RefCell<Vec<usize>>);

impl Trace {
	pub(super) fn sizes(&self) -> Vec<usize> {
		self.0.borrow().clone()
	}
}

pub(super) struct Stage<'test> {
	length: u64,
	bytes: Vec<u8>,
	trace: &'test Trace,
}

impl<'test> Stage<'test> {
	pub(super) const fn new(trace: &'test Trace, length: u64) -> Self {
		Self {
			length,
			bytes: Vec::new(),
			trace,
		}
	}
}

impl FreshStage for Stage<'_> {
	type Error = io::Error;
	type Closed = Sealed;

	const MAX_CHUNK_BYTES: usize = 3;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		assert!(self.bytes.is_empty());
		Ok(self.length)
	}

	fn write_next(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
		assert!((1..=Self::MAX_CHUNK_BYTES).contains(&bytes.len()));
		self.trace.0.borrow_mut().push(bytes.len());
		self.bytes.extend_from_slice(bytes);
		Ok(())
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		assert_eq!(self.bytes.len() as u64, self.length);
		Ok(Sealed(self.bytes))
	}
}

impl CheckpointStage for Stage<'_> {
	type Binding = u8;

	fn sync_prefix(&mut self, end: u64) -> Result<Self::Binding, Self::Error> {
		assert_eq!(end, self.bytes.len() as u64);
		Ok(4)
	}
}

#[derive(Debug)]
pub(super) struct Sealed(Vec<u8>);

impl Sealed {
	pub(super) fn bytes(&self) -> &[u8] {
		&self.0
	}
}

impl ClosedStage for Sealed {
	type Error = io::Error;
	type Reader<'stage> = ReadBack<'stage>;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		Ok(ReadBack(&self.0))
	}
}

pub(super) struct ReadBack<'a>(&'a [u8]);

impl ReadView for ReadBack<'_> {
	type Error = io::Error;

	fn length(&self) -> u64 {
		self.0.len() as u64
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		let start = usize::try_from(offset).unwrap();
		bytes.copy_from_slice(&self.0[start..start + bytes.len()]);
		Ok(())
	}
}

#[derive(Default)]
pub(super) struct Checkpoints {
	pub(super) ranges: Vec<CaptureCheckpoint>,
}

impl CaptureCheckpoints<u8> for Checkpoints {
	type Error = io::Error;

	fn record(&mut self, binding: u8, range: CaptureCheckpoint) -> Result<(), Self::Error> {
		assert_eq!(binding, 4);
		self.ranges.push(range);
		Ok(())
	}
}
