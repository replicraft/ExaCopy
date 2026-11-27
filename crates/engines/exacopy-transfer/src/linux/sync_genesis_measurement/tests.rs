use std::cell::Cell;
use std::convert::Infallible;

use exacopy_endpoint::UnixComponent;
use exacopy_plan::workflow_sync::LinuxLocation;

use super::*;

struct MemoryView {
	content: &'static [u8],
	reads: Cell<u32>,
	checks: Cell<u32>,
}

impl ReadView for MemoryView {
	type Error = Infallible;

	fn length(&self) -> u64 {
		u64::try_from(self.content.len()).unwrap()
	}

	fn read_exact_at(&self, offset: u64, scratch: &mut [u8]) -> Result<(), Self::Error> {
		self.reads.set(self.reads.get() + 1);
		let start = usize::try_from(offset).unwrap();
		scratch.copy_from_slice(&self.content[start..start + scratch.len()]);
		Ok(())
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.checks.set(self.checks.get() + 1);
		Ok(())
	}
}

struct TestPair {
	selection: LiveSyncSelection<'static>,
	views: [MemoryView; 2],
	facts: [GenesisFileFacts; 2],
	absent: bool,
	visits: Cell<u32>,
	fail_at: u32,
}

impl TestPair {
	fn new(content: [&'static [u8]; 2]) -> Self {
		let selection = LiveSyncSelection {
			profile: [1; 16],
			revision: NonZeroU64::MIN,
			owner_key: [2; 32],
			subject: UnixComponent::new(b"subject").unwrap(),
			endpoints: [
				endpoint(0, b"left", object(11)),
				endpoint(1, b"right", object(12)),
			],
		};
		let views = content.map(|content| MemoryView {
			content,
			reads: Cell::new(0),
			checks: Cell::new(0),
		});
		let timestamp = WorkflowTimestamp::new(-1, 999_999_999).unwrap();
		let facts = [0, 1].map(|index| GenesisFileFacts {
			object: object(if index == 0 { 20 } else { 21 }),
			native_mode: 0o100_640,
			length: views[index].length(),
			uid: 501,
			gid: 502,
			links: 1,
			modified: timestamp,
			changed: timestamp,
		});
		Self {
			selection,
			views,
			facts,
			absent: false,
			visits: Cell::new(0),
			fail_at: 0,
		}
	}

	fn assert_no_reads(&self) {
		assert!(self.views.iter().all(|view| view.reads.get() == 0));
	}
}

impl HeldGenesisPair for TestPair {
	type View = MemoryView;
	type Error = &'static str;

	fn observations(&self) -> [GenesisInput<'_, Self::View>; 2] {
		[0, 1].map(|index| {
			if index == 1 && self.absent {
				GenesisInput::Absent
			} else {
				GenesisInput::Present {
					view: &self.views[index],
					facts: self.facts[index],
				}
			}
		})
	}

	fn recheck_selection(&self) -> Result<LiveSyncSelection<'_>, Self::Error> {
		let visit = self.visits.get() + 1;
		self.visits.set(visit);
		if visit == self.fail_at {
			return Err("pair drift");
		}
		Ok(self.selection)
	}
}

fn endpoint(index: u8, name: &'static [u8], root: NativeObject) -> EndpointFacts<'static> {
	EndpointFacts {
		endpoint: [3 + index; 16],
		root: [5 + index; 16],
		parent: [7; 16],
		name: UnixComponent::new(name).unwrap(),
		location: LinuxLocation {
			boot: [8; 16],
			mount_namespace: object(4),
			user_namespace: object(5),
			mount: NonZeroU64::MIN,
			parent: object(10),
			root,
		},
		max_bytes: 8,
	}
}

fn object(inode: u64) -> NativeObject {
	NativeObject {
		major: 4,
		minor: 8,
		inode: NonZeroU64::new(inode).unwrap(),
	}
}

#[test]
fn measures_each_original_view_and_retains_the_final_recheck_capability() {
	let mut pair = TestPair::new([b"contents", b"contents"]);
	pair.fail_at = 3;
	let token = measure_genesis_pair(&pair, pair.selection, &mut [0; 3]).unwrap();
	let [left, right] = token.sides();
	assert_eq!(token.selection(), pair.selection);
	assert_eq!(left.measured.position.get(), 1);
	assert_eq!(right.measured.position.get(), 2);
	assert_eq!(left.rechecked.position.get(), 3);
	assert_eq!(right.rechecked.position.get(), 3);
	assert_eq!(left.measured.stability, left.rechecked.stability);
	assert_eq!(right.measured.stability, right.rechecked.stability);
	assert_ne!(left.measured.stability, right.measured.stability);
	assert_ne!(left.measured.identity.file, right.measured.identity.file);
	assert_eq!(left.metadata.mode, 0o640);
	assert_eq!(left.metadata_digest, right.metadata_digest);
	assert_eq!(left.stream_digest, *blake3::hash(b"contents").as_bytes());
	for view in &pair.views {
		assert_eq!(view.reads.get(), 3);
		assert_eq!(view.checks.get(), 2);
	}
	assert_eq!(pair.visits.get(), 2);
	assert!(matches!(
		token.recheck(),
		Err(GenesisMeasureFailure::Pair("pair drift"))
	));
}

#[test]
fn empty_streams_still_bracket_both_observations() {
	let pair = TestPair::new([b"", b""]);
	let token = measure_genesis_pair(&pair, pair.selection, &mut [0; 1]).unwrap();
	assert!(
		token.sides().iter().all(|side| {
			side.length == 0 && side.stream_digest == *blake3::hash(b"").as_bytes()
		})
	);
	for view in &pair.views {
		assert_eq!(view.reads.get(), 0);
		assert_eq!(view.checks.get(), 2);
	}
}

#[test]
fn refuses_bad_scope_inputs_before_full_reads() {
	use GenesisMeasureFailure as Failure;
	use SyncSide::Right;

	let mut pair = TestPair::new([b"data", b"data"]);
	let mut wrong_scope = pair.selection;
	wrong_scope.endpoints.swap(0, 1);
	assert!(matches!(
		measure_genesis_pair(&pair, wrong_scope, &mut [0; 1]),
		Err(Failure::Selection)
	));
	pair.selection.endpoints[1].max_bytes = 3;
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 1]),
		Err(Failure::FileLimit(Right))
	));
	pair.selection.endpoints[1].max_bytes = 4;
	pair.absent = true;
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 1]),
		Err(Failure::Absent(Right))
	));
	pair.absent = false;
	pair.facts[1].links = 2;
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 1]),
		Err(Failure::Unsupported(Right))
	));
	pair.facts[1].links = 1;
	pair.facts[1].native_mode |= 0o4000;
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 1]),
		Err(Failure::Unsupported(Right))
	));
	pair.facts[1].native_mode = pair.facts[0].native_mode;
	pair.facts[1].object = pair.facts[0].object;
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 1]),
		Err(Failure::Alias)
	));
	pair.assert_no_reads();
}

#[test]
fn refuses_unmatched_content_metadata_and_drift_after_both_reads() {
	use GenesisMeasureFailure as Failure;

	let pair = TestPair::new([b"data", b"edit"]);
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 2]),
		Err(Failure::ContentMismatch)
	));
	let mut pair = TestPair::new([b"data", b"data"]);
	pair.facts[1].native_mode = 0o100_600;
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 2]),
		Err(Failure::MetadataMismatch)
	));
	let mut pair = TestPair::new([b"data", b"data"]);
	pair.fail_at = 2;
	assert!(matches!(
		measure_genesis_pair(&pair, pair.selection, &mut [0; 2]),
		Err(Failure::Pair("pair drift"))
	));
	assert!(pair.views.iter().all(|view| view.reads.get() == 2));
}
