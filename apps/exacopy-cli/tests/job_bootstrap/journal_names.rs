use std::cell::Cell;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};
use exacopy_journal::{DurableJournal, DurableJournalError};
use exacopy_platform::linux::LinuxJournalSegment;

use super::{
	DestinationFixture, DirBuilder, FIRST_SEGMENT, FrameKind, JOB_DIRECTORY, JOURNAL, OpenOptions,
	PRIVATE_DIRECTORY_MODE, PRIVATE_FILE_MODE, Path, PathBuf, StageError, TARGET, assert_absent,
	bootstrap, fs, native_identity,
};

const ORIGINAL: &[u8] = b"original fixture envelope payload";
const FOLLOWUP: &[u8] = b"fixture followup must never be appended";
const RETAINED: &str = "retained-original-alias";

#[derive(Debug, Clone, Copy)]
enum Alias {
	Job,
	Journal,
	Segment,
}

#[test]
fn fresh_writer_refuses_each_same_byte_native_alias_rebound() {
	for alias in [Alias::Job, Alias::Journal, Alias::Segment] {
		for verify in [true, false] {
			check_displacement(alias, verify);
		}
	}
}

fn check_displacement(alias: Alias, verify: bool) {
	let fixture = DestinationFixture::new();
	let mut writer = DurableJournal::from_new_segment(fresh_segment(&fixture)).unwrap();
	let synced = writer.append(FrameKind::JobPrepared, ORIGINAL).unwrap();
	writer.confirm_current_frame(&synced).unwrap();

	let job = fixture.path(JOB_DIRECTORY);
	let journal = job.join(JOURNAL);
	let segment = journal.join(FIRST_SEGMENT);
	let original_bytes = fs::read(&segment).unwrap();
	let original_segment = native_identity(&fs::symlink_metadata(&segment).unwrap());
	let displaced = match alias {
		Alias::Job => &job,
		Alias::Journal => &journal,
		Alias::Segment => &segment,
	};
	let original_alias = native_identity(&fs::symlink_metadata(displaced).unwrap());
	let retained = fixture.path(RETAINED);
	assert_absent(&retained);
	// Deliberately violate the cooperative lease in this disposable owned fixture. The former
	// name remains occupied by a separately created object with identical segment bytes.
	fs::rename(displaced, &retained).unwrap();
	let retained_segment = rebind(alias, &job, &journal, &retained);
	OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(PRIVATE_FILE_MODE)
		.open(&segment)
		.unwrap()
		.write_all(&original_bytes)
		.unwrap();
	let rebound_alias = native_identity(&fs::symlink_metadata(displaced).unwrap());
	let rebound_segment = native_identity(&fs::symlink_metadata(&segment).unwrap());
	assert_ne!(original_alias, rebound_alias);
	assert_ne!(original_segment, rebound_segment);

	let refusal = if verify {
		writer.confirm_current_frame(&synced)
	} else {
		writer
			.append(FrameKind::EntryPrepared, FOLLOWUP)
			.map(|_| ())
	};
	assert!(
		is_identity_refusal(&refusal),
		"{alias:?} verify={verify}: {refusal:?}"
	);
	assert!(matches!(
		writer.append(FrameKind::EntryPrepared, FOLLOWUP),
		Err(DurableJournalError::Retired)
	));
	assert_eq!(
		native_identity(&fs::symlink_metadata(retained).unwrap()),
		original_alias
	);
	assert_eq!(
		native_identity(&fs::symlink_metadata(displaced).unwrap()),
		rebound_alias
	);
	assert_eq!(
		native_identity(&fs::symlink_metadata(&retained_segment).unwrap()),
		original_segment
	);
	assert_eq!(
		native_identity(&fs::symlink_metadata(&segment).unwrap()),
		rebound_segment
	);
	assert_eq!(fs::read(retained_segment).unwrap(), original_bytes);
	assert_eq!(fs::read(segment).unwrap(), original_bytes);
	assert_absent(&fixture.path(TARGET));
}

fn rebind(alias: Alias, job: &Path, journal: &Path, retained: &Path) -> PathBuf {
	let private_directory = |path: &Path| {
		DirBuilder::new()
			.mode(PRIVATE_DIRECTORY_MODE)
			.create(path)
			.unwrap()
	};
	match alias {
		Alias::Job => {
			private_directory(job);
			private_directory(journal);
			retained.join(JOURNAL).join(FIRST_SEGMENT)
		}
		Alias::Journal => {
			private_directory(journal);
			retained.join(FIRST_SEGMENT)
		}
		Alias::Segment => retained.to_path_buf(),
	}
}

fn fresh_segment(fixture: &DestinationFixture) -> LinuxJournalSegment<'static> {
	let destination = fixture.open_root();
	let job = destination
		.create_job_directory(bootstrap(JOB_DIRECTORY).name)
		.unwrap();
	let journal = job.create_journal_directory().unwrap();
	journal.create_first_segment().unwrap()
}

fn is_identity_refusal(result: &Result<(), DurableJournalError>) -> bool {
	matches!(
		result,
		Err(DurableJournalError::Inspect(error))
			if matches!(
				error.get_ref().and_then(|error| error.downcast_ref::<StageError>()),
				Some(StageError::IdentityChanged)
			)
	)
}

#[test]
fn fresh_writer_checks_live_names_again_after_reading_the_exact_prefix() {
	let fixture = DestinationFixture::new();
	let selected = fixture
		.path(JOB_DIRECTORY)
		.join(JOURNAL)
		.join(FIRST_SEGMENT);
	let retained = fixture.path(RETAINED);
	let moved = Cell::new(false);
	let mut writer = DurableJournal::from_new_segment(MoveOnRead {
		native: fresh_segment(&fixture),
		selected: &selected,
		retained: &retained,
		moved: &moved,
	})
	.unwrap();
	let synced = writer.append(FrameKind::JobPrepared, ORIGINAL).unwrap();
	let original = fs::read(&selected).unwrap();
	let identity = native_identity(&fs::symlink_metadata(&selected).unwrap());

	let result = writer.confirm_current_frame(&synced);
	assert!(is_identity_refusal(&result), "{result:?}");
	assert!(
		moved.get(),
		"preflight must succeed and invoke the read before refusal"
	);
	assert!(matches!(
		writer.append(FrameKind::EntryPrepared, FOLLOWUP),
		Err(DurableJournalError::Retired)
	));
	assert_eq!(
		native_identity(&fs::symlink_metadata(&retained).unwrap()),
		identity
	);
	assert_ne!(
		native_identity(&fs::symlink_metadata(&selected).unwrap()),
		identity
	);
	assert_eq!(fs::read(retained).unwrap(), original);
	assert_eq!(fs::read(selected).unwrap(), original);
	assert_absent(&fixture.path(TARGET));
}

struct MoveOnRead<'fixture> {
	native: LinuxJournalSegment<'static>,
	selected: &'fixture Path,
	retained: &'fixture Path,
	moved: &'fixture Cell<bool>,
}

impl Read for MoveOnRead<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if !self.moved.replace(true) {
			assert_absent(self.retained);
			fs::rename(self.selected, self.retained).unwrap();
			let bytes = fs::read(self.retained).unwrap();
			OpenOptions::new()
				.create_new(true)
				.write(true)
				.mode(PRIVATE_FILE_MODE)
				.open(self.selected)
				.unwrap()
				.write_all(&bytes)
				.unwrap();
		}
		self.native.read(output)
	}
}

impl Write for MoveOnRead<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.native.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.native.flush()
	}
}

impl Seek for MoveOnRead<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.native.seek(position)
	}
}

impl JournalSegment for MoveOnRead<'_> {
	const BARRIER: JournalFileBarrier = LinuxJournalSegment::BARRIER;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		self.native.regular_length()
	}

	fn sync(&self) -> io::Result<()> {
		self.native.sync()
	}
}
