use std::cell::RefCell;
use std::convert::Infallible;
use std::io;

use exacopy_endpoint::{IoError, ReadView};
use exacopy_model::{EntryId, JobId, RunEpoch, StageId};

use super::*;

const STAGE_IDENTITY: u8 = 2;
const CHECKPOINT_LENGTH: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
	SourceAttributes,
	SourceChecked,
	Create,
	CheckOwnership,
	SyncPreparationDirectory,
	Prepare,
	Read,
	Write,
	RecheckForCheckpoint,
	Flush,
	Checkpoint,
	Resize,
	CloseWriter,
	ReadBack,
	ApplyMetadata,
	SyncSealedDirectory,
}

type Trace = RefCell<Vec<Effect>>;

struct Source<'a> {
	trace: &'a Trace,
	length: u64,
}

impl ReadView for Source<'_> {
	type Error = Infallible;

	fn length(&self) -> u64 {
		self.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Effect::SourceChecked);
		Ok(())
	}

	fn read_exact_at(&self, _: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Effect::Read);
		bytes.fill(7);
		Ok(())
	}
}

#[derive(Debug, Clone, Copy)]
struct Metadata;

impl SourceMetadata for Metadata {
	type Timestamp = u8;

	fn mode(self) -> u32 {
		0o640
	}

	fn accessed_at(self) -> u8 {
		42
	}
}

impl StagingSource for Source<'_> {
	type Identity = u8;
	type Metadata = Metadata;

	fn identity(&self) -> u8 {
		1
	}

	fn metadata(&self) -> Metadata {
		Metadata
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error> {
		self.trace.borrow_mut().push(Effect::SourceAttributes);
		Ok(ExtendedAttributes::NoneVisible)
	}

	fn recheck_metadata(&self) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Effect::RecheckForCheckpoint);
		Ok(())
	}
}

struct Directory<'a> {
	trace: &'a Trace,
	readback: u8,
}

impl StagingDirectory for Directory<'_> {
	type Error = io::Error;
	type Identity = u8;
	type Metadata = Metadata;
	type Writer<'stage>
		= Writer<'stage>
	where
		Self: 'stage;

	fn create_file(
		&self,
		_: UnixComponent<'_>,
		_: UnixComponent<'_>,
		_: CopyBinding,
	) -> Result<Self::Writer<'_>, io::Error> {
		self.trace.borrow_mut().push(Effect::Create);
		Ok(Writer {
			trace: self.trace,
			length: 0,
			readback: self.readback,
		})
	}

	fn sync_directory(&self) -> Result<(), io::Error> {
		self.trace
			.borrow_mut()
			.push(Effect::SyncPreparationDirectory);
		Ok(())
	}
}

struct Writer<'a> {
	trace: &'a Trace,
	length: u64,
	readback: u8,
}

impl<'a> StageWriter for Writer<'a> {
	type Identity = u8;
	type Metadata = Metadata;
	type Error = io::Error;
	type Reader = Reader<'a>;

	fn identity(&self) -> u8 {
		STAGE_IDENTITY
	}

	fn check_ownership(&self, _: Metadata) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Effect::CheckOwnership);
		Ok(())
	}

	fn write_all_at(&mut self, _: u64, bytes: &[u8]) -> Result<(), Self::Error> {
		assert_eq!(bytes.first(), Some(&7));
		assert_eq!(bytes.last(), Some(&7));
		self.trace.borrow_mut().push(Effect::Write);
		Ok(())
	}

	fn set_len(&mut self, length: u64) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Effect::Resize);
		self.length = length;
		Ok(())
	}

	fn flush(&mut self) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Effect::Flush);
		Ok(())
	}

	fn close_writes(self) -> Result<Self::Reader, Self::Error> {
		self.trace.borrow_mut().push(Effect::CloseWriter);
		Ok(Reader {
			trace: self.trace,
			length: self.length,
			readback: self.readback,
		})
	}
}

#[derive(Debug)]
struct Reader<'a> {
	trace: &'a Trace,
	length: u64,
	readback: u8,
}

impl StageReader for Reader<'_> {
	type Identity = u8;
	type Metadata = Metadata;
	type Error = io::Error;

	fn identity(&self) -> u8 {
		STAGE_IDENTITY
	}

	fn length(&self) -> u64 {
		self.length
	}

	fn read_exact_at(&self, _: u64, bytes: &mut [u8]) -> Result<(), IoError> {
		self.trace.borrow_mut().push(Effect::ReadBack);
		bytes.fill(self.readback);
		Ok(())
	}

	fn apply_metadata_with_access_time(
		self,
		_: Metadata,
		accessed_at: u8,
	) -> Result<Self, Self::Error> {
		assert_eq!(
			accessed_at, 42,
			"metadata must use the captured access time"
		);
		self.trace.borrow_mut().push(Effect::ApplyMetadata);
		Ok(self)
	}

	fn sync_stage_directory(&self) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(Effect::SyncSealedDirectory);
		Ok(())
	}
}

struct Records<'a> {
	trace: &'a Trace,
	next_offset: u64,
}

impl StageRecords<u8, Infallible, io::Error> for Records<'_> {
	fn begin(
		&mut self,
		stage: u8,
	) -> Result<SourceMeasurementId, StageFailure<Infallible, io::Error>> {
		assert_eq!(
			stage, STAGE_IDENTITY,
			"preparation must bind the created stage"
		);
		self.trace.borrow_mut().push(Effect::Prepare);
		Ok(SourceMeasurementId::from_prepared_payload(
			b"fixture source",
		))
	}

	fn record(
		&mut self,
		measurement: SourceMeasurementId,
		range: RangeMeasurement,
	) -> Result<(), StageFailure<Infallible, io::Error>> {
		assert_eq!(
			measurement,
			SourceMeasurementId::from_prepared_payload(b"fixture source")
		);
		assert_eq!(range.offset, self.next_offset);
		assert!(range.length > 0);
		self.next_offset += range.length;
		assert!(self.next_offset <= CHECKPOINT_LENGTH);
		self.trace.borrow_mut().push(Effect::Checkpoint);
		Ok(())
	}
}

fn request() -> StageRequest<'static> {
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	StageRequest {
		stage_name: UnixComponent::new(b"stage").expect("valid stage name"),
		target: UnixComponent::new(b"target").expect("valid target name"),
		binding: CopyBinding::new(
			job,
			EntryId::new(1),
			RunEpoch::new(1),
			StageId::from_bytes([0x53; 16]),
		),
	}
}

#[test]
fn records_checkpoint_after_data_barrier_and_releases_writer_before_readback() {
	use Effect::*;

	let trace = Trace::default();
	let source = Source {
		trace: &trace,
		length: CHECKPOINT_LENGTH,
	};
	let directory = Directory {
		trace: &trace,
		readback: 7,
	};
	let mut records = Records {
		trace: &trace,
		next_offset: 0,
	};
	let mut scratch = vec![0; exacopy_content::MAX_SCRATCH_BYTES];
	let stage = stage_verified(
		&source,
		&directory,
		request(),
		&mut scratch,
		Some(&mut records),
	)
	.expect("matching independent read-back must seal this fixture");
	assert_eq!(stage.identity(), STAGE_IDENTITY);
	assert_eq!(stage.length(), CHECKPOINT_LENGTH);
	assert_eq!(stage.phase(), CopyPhase::ReadyToPublish);
	let trace = trace.borrow();
	assert_eq!(
		&trace[..6],
		&[
			SourceAttributes,
			SourceChecked,
			Create,
			CheckOwnership,
			SyncPreparationDirectory,
			Prepare
		],
	);
	let finish = trace
		.iter()
		.position(|effect| *effect == Resize)
		.expect("resize to the final stream length");
	// A time-based checkpoint can occur first on a loaded test machine.
	assert!(trace[..finish].contains(&Checkpoint));
	for (index, effect) in trace.iter().enumerate().take(finish) {
		if *effect == Checkpoint {
			assert_eq!(
				&trace[index - 3..index],
				&[Write, RecheckForCheckpoint, Flush]
			);
		}
	}
	assert_eq!(
		&trace[finish..finish + 4],
		&[Resize, Flush, CloseWriter, ReadBack]
	);
	assert_eq!(
		&trace[trace.len() - 7..],
		&[
			ReadBack,
			SourceAttributes,
			SourceChecked,
			ApplyMetadata,
			SyncSealedDirectory,
			SourceAttributes,
			SourceChecked
		]
	);
}

#[test]
fn staging_carries_both_actual_digest_and_length_observations() {
	let trace = Trace::default();
	let source = Source {
		trace: &trace,
		length: 17,
	};
	let directory = Directory {
		trace: &trace,
		readback: 7,
	};
	let stage = stage_verified(&source, &directory, request(), &mut [0; 5], None).unwrap();
	let streams = stage.observed_streams();
	assert_eq!(streams.source_length, 17);
	assert_eq!(streams.stage_length, 17);
	let expected = *blake3::hash(&[7; 17]).as_bytes();
	assert_eq!(streams.source_digest.as_bytes(), &expected);
	assert_eq!(streams.stage_digest.as_bytes(), &expected);
	let trace = trace.borrow();
	assert!(
		trace
			.iter()
			.position(|effect| *effect == Effect::CloseWriter)
			.unwrap()
			< trace
				.iter()
				.position(|effect| *effect == Effect::ReadBack)
				.unwrap()
	);
}

#[test]
fn readback_mismatch_stops_before_metadata_and_sealing() {
	use Effect::*;

	let trace = Trace::default();
	let source = Source {
		trace: &trace,
		length: 3,
	};
	let directory = Directory {
		trace: &trace,
		readback: 0,
	};
	let error = stage_verified(&source, &directory, request(), &mut [0; 3], None)
		.expect_err("different independent read-back must fail verification");
	assert!(matches!(error.failure(), StageFailure::DigestMismatch));
	assert_eq!(error.phase(), CopyPhase::DataFlushed);
	assert_eq!(
		*trace.borrow(),
		[
			SourceAttributes,
			SourceChecked,
			Create,
			CheckOwnership,
			Read,
			Write,
			Resize,
			Flush,
			CloseWriter,
			ReadBack
		],
	);
}
