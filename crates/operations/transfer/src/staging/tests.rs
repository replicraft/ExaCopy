use std::cell::RefCell;

use exacopy_endpoint::{ClosedStage, FreshStage, MetadataSource, ReadView, RequiredMetadataStage};

use super::{StageCopyFailure, copy_fresh_with_metadata};

const PAYLOAD: [u8; 3] = *b"abc";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
	AdmitMetadata,
	AdmitStage,
	CheckSource,
	ReadSource,
	WriteStage,
	CloseStage,
	OpenReadBack,
	ReadStage,
	CheckReadBack,
	RecheckSource,
	ApplyMetadata,
}

#[derive(Debug, Default)]
struct Fixture {
	actions: RefCell<Vec<Action>>,
	fail_at: Option<Action>,
	corrupt_read_back: bool,
	read_back_length: Option<u64>,
}

impl Fixture {
	fn observe(&self, action: Action) -> Result<(), Action> {
		self.actions.borrow_mut().push(action);
		if self.fail_at == Some(action) {
			return Err(action);
		}
		Ok(())
	}
	fn writer(&self) -> Writer<'_> {
		Writer {
			fixture: self,
			bytes: Vec::new(),
		}
	}
}

struct Source<'fixture>(&'fixture Fixture);

impl ReadView for Source<'_> {
	type Error = Action;

	fn length(&self) -> u64 {
		PAYLOAD.len() as u64
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		let action = if self.0.actions.borrow().contains(&Action::CheckSource) {
			Action::RecheckSource
		} else {
			Action::CheckSource
		};
		self.0.observe(action)
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.0.observe(Action::ReadSource)?;
		let start = usize::try_from(offset).unwrap();
		buffer.copy_from_slice(&PAYLOAD[start..start + buffer.len()]);
		Ok(())
	}
}

impl MetadataSource for Source<'_> {
	fn admit_metadata(&self) -> Result<(), Self::Error> {
		self.0.observe(Action::AdmitMetadata)
	}
}

struct Writer<'fixture> {
	fixture: &'fixture Fixture,
	bytes: Vec<u8>,
}

impl<'fixture> FreshStage for Writer<'fixture> {
	type Error = Action;
	type Closed = Closed<'fixture>;
	const MAX_CHUNK_BYTES: usize = 2;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		self.fixture.observe(Action::AdmitStage)?;
		Ok(PAYLOAD.len() as u64)
	}

	fn write_next(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.fixture.observe(Action::WriteStage)?;
		assert!(buffer.len() <= Self::MAX_CHUNK_BYTES);
		self.bytes.extend_from_slice(buffer);
		Ok(())
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		self.fixture.observe(Action::CloseStage)?;
		assert_eq!(self.bytes.len(), PAYLOAD.len());
		Ok(Closed {
			fixture: self.fixture,
			bytes: self.bytes,
		})
	}
}

struct Closed<'fixture> {
	fixture: &'fixture Fixture,
	bytes: Vec<u8>,
}

impl ClosedStage for Closed<'_> {
	type Error = Action;
	type Reader<'stage>
		= Reader<'stage>
	where
		Self: 'stage;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.fixture.observe(Action::OpenReadBack)?;
		Ok(Reader(self))
	}
}

impl RequiredMetadataStage<Source<'_>> for Closed<'_> {
	type Ready = Vec<u8>;

	fn apply_metadata(self, source: &Source<'_>) -> Result<Self::Ready, Self::Error> {
		assert!(std::ptr::eq(self.fixture, source.0));
		self.fixture.observe(Action::ApplyMetadata)?;
		Ok(self.bytes)
	}
}

struct Reader<'stage>(&'stage Closed<'stage>);

impl ReadView for Reader<'_> {
	type Error = Action;

	fn length(&self) -> u64 {
		self.0
			.fixture
			.read_back_length
			.unwrap_or(self.0.bytes.len() as u64)
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.0.fixture.observe(Action::CheckReadBack)
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.0.fixture.observe(Action::ReadStage)?;
		let start = usize::try_from(offset).unwrap();
		buffer.copy_from_slice(&self.0.bytes[start..start + buffer.len()]);
		if self.0.fixture.corrupt_read_back && offset == 0 {
			buffer[0] ^= 0xff;
		}
		Ok(())
	}
}

#[test]
fn streams_in_order_and_installs_metadata_after_verified_read_back() {
	let fixture = Fixture::default();
	let result = copy_fresh_with_metadata(&Source(&fixture), fixture.writer(), &mut [0; 2])
		.expect("the stage should verify");
	let (stage, source, read_back) = result.into_parts();
	assert_eq!(stage, PAYLOAD);
	assert_eq!(source.as_bytes(), blake3::hash(&PAYLOAD).as_bytes());
	assert_eq!(source, read_back);
	assert_eq!(
		fixture.actions.into_inner(),
		[
			Action::AdmitMetadata,
			Action::AdmitStage,
			Action::CheckSource,
			Action::ReadSource,
			Action::WriteStage,
			Action::ReadSource,
			Action::WriteStage,
			Action::CloseStage,
			Action::OpenReadBack,
			Action::ReadStage,
			Action::ReadStage,
			Action::CheckReadBack,
			Action::RecheckSource,
			Action::ApplyMetadata,
		]
	);
}

#[test]
fn stops_at_the_first_failed_staging_boundary() {
	for action in [
		Action::AdmitMetadata,
		Action::CloseStage,
		Action::CheckReadBack,
		Action::RecheckSource,
		Action::ApplyMetadata,
	] {
		let fixture = Fixture {
			fail_at: Some(action),
			..Fixture::default()
		};
		let error = copy_fresh_with_metadata(&Source(&fixture), fixture.writer(), &mut [0; 2])
			.expect_err("the first failed observation must end the operation");
		match (action, error) {
			(Action::AdmitMetadata, StageCopyFailure::AdmitMetadata(Action::AdmitMetadata))
			| (Action::CloseStage, StageCopyFailure::CloseStage(Action::CloseStage))
			| (
				Action::CheckReadBack,
				StageCopyFailure::RevalidateReadBack(Action::CheckReadBack),
			)
			| (Action::RecheckSource, StageCopyFailure::RevalidateSource(Action::RecheckSource))
			| (Action::ApplyMetadata, StageCopyFailure::ApplyMetadata(Action::ApplyMetadata)) => {}
			(_, failure) => panic!("unexpected error at {action:?}: {failure:?}"),
		}
		let actions = fixture.actions.into_inner();
		assert_eq!(actions.last(), Some(&action));
		if action != Action::ApplyMetadata {
			assert!(!actions.contains(&Action::ApplyMetadata));
		}
	}
}

#[test]
fn rejects_scratch_above_the_injected_chunk_limit_before_copying() {
	let fixture = Fixture::default();
	let error = copy_fresh_with_metadata(&Source(&fixture), fixture.writer(), &mut [0; 3])
		.expect_err("scratch must respect the stage adapter's limit");
	assert!(matches!(
		error,
		StageCopyFailure::ScratchTooLarge { length: 3 }
	));
	assert_eq!(
		fixture.actions.into_inner(),
		[Action::AdmitMetadata, Action::AdmitStage]
	);
}

#[test]
fn refuses_disagreeing_read_back_bytes_or_extent() {
	let fixture = Fixture {
		corrupt_read_back: true,
		..Fixture::default()
	};
	let error = copy_fresh_with_metadata(&Source(&fixture), fixture.writer(), &mut [0; 2])
		.expect_err("changed read-back bytes must fail verification");
	assert!(matches!(error, StageCopyFailure::DigestMismatch { .. }));
	assert_eq!(
		fixture.actions.into_inner().last(),
		Some(&Action::CheckReadBack)
	);

	let fixture = Fixture {
		read_back_length: Some(0),
		..Fixture::default()
	};
	let error = copy_fresh_with_metadata(&Source(&fixture), fixture.writer(), &mut [0; 2])
		.expect_err("changed read-back extent must fail verification");
	assert!(matches!(
		error,
		StageCopyFailure::ReadBackExtentMismatch {
			stage_length: 3,
			read_back_length: 0
		}
	));
	assert_eq!(
		fixture.actions.into_inner().last(),
		Some(&Action::OpenReadBack)
	);
}
