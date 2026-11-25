//! Modeled volatile-storage loss at each barrier of a single checkpoint.

use exacopy_endpoint::UnixComponent;
use exacopy_testkit::{
	Area, DiskId, EffectError, EffectFault, EffectOperation, Entry, Failure, Simulator, Snapshot,
	StageWriter, WritableArea,
};

const DATA: &[u8] = b"copied prefix";
const PAGE_BYTES: &[u8] = b"range page fixture";
const FRAME_BYTES: &[u8] = b"range frame fixture";
const INCUMBENT: &[u8] = b"other owner's file";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Barrier {
	StageFile,
	PageFile,
	PageDirectory,
	JournalFrame,
}

impl Barrier {
	const ORDER: [Self; 4] = [
		Self::StageFile,
		Self::PageFile,
		Self::PageDirectory,
		Self::JournalFrame,
	];
}

#[test]
fn checkpoint_barrier_failures_leave_only_the_completed_stable_prefix() {
	for (completed_before_stop, stop) in Barrier::ORDER.into_iter().enumerate() {
		for reason in [Failure::Io, Failure::NoSpace] {
			for (fault, expected_error, effect_completed) in [
				(
					EffectFault::Before(reason),
					EffectError::Failed(reason),
					false,
				),
				(
					EffectFault::After(reason),
					EffectError::Unknown(reason),
					true,
				),
			] {
				check(
					Some((stop, fault)),
					Err(expected_error),
					completed_before_stop + usize::from(effect_completed),
				);
			}
		}
	}
	check(None, Ok(()), Barrier::ORDER.len());
}

fn check(
	fault: Option<(Barrier, EffectFault)>,
	expected_result: Result<(), EffectError>,
	expected_stable_barriers: usize,
) {
	let (mut storage, names, writers) = fixture();
	let initial = storage.live_snapshot();
	let actual = record_checkpoint(&mut storage, &names, writers, fault);
	assert_eq!(actual, expected_result, "{fault:?}");

	let live = storage.live_snapshot();
	let frame_attempted = fault.is_none_or(|(at, _)| at == Barrier::JournalFrame);
	assert_eq!(
		file_bytes(&live, Area::Private, &names.journal),
		Some(if frame_attempted { FRAME_BYTES } else { b"" }),
		"{fault:?}"
	);
	storage.process_crash();
	assert_eq!(storage.live_snapshot(), live, "{fault:?}");
	let stable = storage.stable_snapshot();
	storage.lose_volatile_state();
	let recovered = storage.live_snapshot();
	assert_eq!(recovered, stable, "{fault:?}");

	assert_eq!(
		recovered.entry(Area::Source, &names.source),
		initial.entry(Area::Source, &names.source)
	);
	assert_eq!(
		recovered.entry(Area::Destination, &names.target),
		initial.entry(Area::Destination, &names.target)
	);
	assert_eq!(
		file_bytes(&recovered, Area::Private, &names.stage),
		Some(if expected_stable_barriers >= 1 {
			DATA
		} else {
			b""
		}),
		"{fault:?}"
	);
	assert_eq!(
		file_bytes(&recovered, Area::Private, &names.page),
		(expected_stable_barriers >= 3).then_some(PAGE_BYTES),
		"{fault:?}"
	);
	assert_eq!(
		file_bytes(&recovered, Area::Private, &names.journal),
		Some(if expected_stable_barriers == 4 {
			FRAME_BYTES
		} else {
			b""
		}),
		"{fault:?}"
	);
}

struct Names {
	source: UnixComponent<'static>,
	target: UnixComponent<'static>,
	stage: UnixComponent<'static>,
	page: UnixComponent<'static>,
	journal: UnixComponent<'static>,
}

struct Writers {
	stage: StageWriter,
	journal: StageWriter,
}

fn fixture() -> (Simulator, Names, Writers) {
	let names = Names {
		source: component(b"source"),
		target: component(b"target"),
		stage: component(b"stage"),
		page: component(b"page"),
		journal: component(b"journal"),
	};
	let mut storage = Simulator::new(DiskId::new(1));
	storage
		.seed_file(Area::Source, &names.source, DATA)
		.unwrap();
	storage
		.seed_file(Area::Destination, &names.target, INCUMBENT)
		.unwrap();
	let stage = storage.create_stage(&names.stage, &names.target).unwrap();
	let journal = storage.create_stage(&names.journal, &names.target).unwrap();
	// Model a retained stage name and a journal segment created before its range record.
	storage.flush_directory(WritableArea::Private).unwrap();
	(storage, names, Writers { stage, journal })
}

// The simulator has no journal codec. These fixed bytes stand for the page and its frame,
// and only their persistence dependencies are under test.
fn record_checkpoint(
	storage: &mut Simulator,
	names: &Names,
	writers: Writers,
	fault: Option<(Barrier, EffectFault)>,
) -> Result<(), EffectError> {
	let inject = |storage: &mut Simulator, barrier, operation| {
		if let Some((at, fault)) = fault
			&& at == barrier
		{
			storage.inject_effect(operation, fault).unwrap();
		}
	};
	write(storage, &writers.stage, DATA);
	inject(storage, Barrier::StageFile, EffectOperation::FlushFile);
	storage.flush_file(&writers.stage.quiesce())?;

	let page = storage.create_stage(&names.page, &names.target).unwrap();
	write(storage, &page, PAGE_BYTES);
	inject(storage, Barrier::PageFile, EffectOperation::FlushFile);
	storage.flush_file(&page.quiesce())?;
	inject(
		storage,
		Barrier::PageDirectory,
		EffectOperation::FlushDirectory,
	);
	storage.flush_directory(WritableArea::Private)?;

	write(storage, &writers.journal, FRAME_BYTES);
	inject(storage, Barrier::JournalFrame, EffectOperation::FlushFile);
	storage.flush_file(&writers.journal.quiesce())
}

fn write(storage: &mut Simulator, writer: &StageWriter, bytes: &[u8]) {
	assert_eq!(storage.write_at(writer, 0, bytes).unwrap(), bytes.len());
}

fn file_bytes<'a>(
	snapshot: &'a Snapshot,
	area: Area,
	name: &UnixComponent<'_>,
) -> Option<&'a [u8]> {
	match snapshot.entry(area, name) {
		Some(Entry::File(file)) => Some(file.bytes),
		Some(Entry::Symlink) => panic!("expected a regular file fixture"),
		None => None,
	}
}

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}
