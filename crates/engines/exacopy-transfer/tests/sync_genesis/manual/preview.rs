use std::cell::{Cell, RefCell};
use std::io::{self, Cursor};

use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_manifest::sync_baseline::LinuxOwnerMode;
use exacopy_model::{SyncConflict, SyncCopyTarget, SyncPathDecision, SyncSide};
use exacopy_plan::workflow_sync::MAX_MEMBER_BYTES;
use exacopy_transfer::linux::sync_preview::{
	HeldSyncPreview, HistoricalPreviewFailure, LiveSyncSelection, MAX_PREVIEW_FILE_BYTES,
	PreviewInput, preview_with_history,
};
use exacopy_transfer::sync_genesis::inspect_selected_sync_genesis;

use super::{extent, first, owner, selected_members};

struct View<'a> {
	bytes: &'a [u8],
	trace: &'a RefCell<Vec<&'static str>>,
	label: &'static str,
	length: u64,
}

impl ReadView for View<'_> {
	type Error = io::Error;

	fn length(&self) -> u64 {
		self.length
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.trace.borrow_mut().push(self.label);
		let start = usize::try_from(offset).unwrap();
		buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
		Ok(())
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		Ok(())
	}
}

struct Pair<'a> {
	current: LiveSyncSelection<'a>,
	final_current: LiveSyncSelection<'a>,
	views: [View<'a>; 2],
	right: RightState,
	final_error: bool,
	rechecks: Cell<u8>,
}

#[derive(Clone, Copy)]
enum RightState {
	Present,
	Absent,
	Unsupported,
}

const METADATA: LinuxOwnerMode = LinuxOwnerMode {
	mode: 0o754,
	uid: u32::MAX,
	gid: 1024,
};

impl<'a> HeldSyncPreview for Pair<'a> {
	type View = View<'a>;
	type Error = io::Error;

	fn observations(&self) -> [PreviewInput<'_, Self::View>; 2] {
		let [left, right] = &self.views;
		[
			PreviewInput::Present {
				view: left,
				metadata: METADATA,
			},
			match self.right {
				RightState::Present => PreviewInput::Present {
					view: right,
					metadata: METADATA,
				},
				RightState::Absent => PreviewInput::Absent,
				RightState::Unsupported => PreviewInput::Unsupported,
			},
		]
	}

	fn recheck_selection(&self) -> Result<LiveSyncSelection<'_>, Self::Error> {
		let trace = self.views[0].trace;
		match self.rechecks.replace(1) {
			0 => {
				trace.borrow_mut().push("initial_scope");
				Ok(self.current)
			}
			_ => {
				trace.borrow_mut().push("final_scope");
				if self.final_error {
					Err(io::ErrorKind::PermissionDenied.into())
				} else {
					Ok(self.final_current)
				}
			}
		}
	}
}

#[test]
fn selected_signed_history_and_live_scope_classify_two_independent_observations() {
	let fixture = first();
	let key = owner();
	let expected = fixture.expected(&key);
	let mut root_buffer = [0; MAX_MEMBER_BYTES];
	let history = inspect_selected_sync_genesis(
		Cursor::new(&fixture.root),
		extent(fixture.root.len()),
		&mut root_buffer,
		&expected,
		selected_members(&fixture),
		|locator| Ok(Cursor::new(&fixture.members[locator])),
	)
	.unwrap();
	let current = LiveSyncSelection {
		profile: expected.profile,
		revision: expected.revision,
		owner_key: key.to_bytes(),
		subject: expected.subject,
		endpoints: expected.endpoints,
	};
	let trace = RefCell::new(Vec::new());
	let mut pair = Pair {
		current,
		final_current: current,
		views: [
			View {
				bytes: b"abc",
				trace: &trace,
				label: "read_left",
				length: 3,
			},
			View {
				bytes: b"xyz",
				trace: &trace,
				label: "read_right",
				length: 3,
			},
		],
		right: RightState::Present,
		final_error: false,
		rechecks: Cell::new(0),
	};
	let result = preview_with_history(&history, &pair, &mut [0; 16]).unwrap();
	assert_eq!(
		result.decision,
		SyncPathDecision::CopyCandidate {
			from: SyncSide::Right,
			target: SyncCopyTarget::ExistingIncumbent
		},
	);
	assert_eq!(
		*trace.borrow(),
		["initial_scope", "read_left", "read_right", "final_scope"]
	);

	trace.borrow_mut().clear();
	pair.right = RightState::Absent;
	pair.rechecks.set(0);
	let result = preview_with_history(&history, &pair, &mut [0; 16]).unwrap();
	assert_eq!(
		result.decision,
		SyncPathDecision::Conflict(SyncConflict::DeletionAgainstUnchanged {
			absent: SyncSide::Right
		}),
	);
	assert_eq!(
		*trace.borrow(),
		["initial_scope", "read_left", "final_scope"]
	);

	trace.borrow_mut().clear();
	pair.right = RightState::Unsupported;
	pair.rechecks.set(0);
	assert!(matches!(
		preview_with_history(&history, &pair, &mut [0; 16]),
		Err(HistoricalPreviewFailure::UnsupportedObservation)
	));
	assert_eq!(*trace.borrow(), ["initial_scope"]);

	pair.right = RightState::Present;
	for drifted in [
		LiveSyncSelection {
			subject: UnixComponent::new(b"other-subject").unwrap(),
			..current
		},
		LiveSyncSelection {
			endpoints: [current.endpoints[1], current.endpoints[0]],
			..current
		},
		LiveSyncSelection {
			owner_key: [3; 32],
			..current
		},
		LiveSyncSelection {
			profile: [3; 16],
			..current
		},
		LiveSyncSelection {
			revision: current.revision.checked_add(1).unwrap(),
			..current
		},
	] {
		trace.borrow_mut().clear();
		pair.current = drifted;
		pair.rechecks.set(0);
		assert!(matches!(
			preview_with_history(&history, &pair, &mut [0; 16]),
			Err(HistoricalPreviewFailure::ScopeMismatch)
		));
		assert_eq!(*trace.borrow(), ["initial_scope"]);
	}

	pair.current = current;
	pair.views[1].length = MAX_PREVIEW_FILE_BYTES + 1;
	pair.rechecks.set(0);
	trace.borrow_mut().clear();
	assert!(matches!(
		preview_with_history(&history, &pair, &mut [0; 16]),
		Err(HistoricalPreviewFailure::Live(
			exacopy_transfer::linux::sync_preview::SyncPreviewFailure::FileLimit(SyncSide::Right)
		))
	));
	assert_eq!(*trace.borrow(), ["initial_scope"]);

	pair.views[1].length = 3;
	pair.final_current.endpoints[0].location.boot[0] ^= 1;
	for final_error in [false, true] {
		trace.borrow_mut().clear();
		pair.rechecks.set(0);
		pair.final_error = final_error;
		let result = preview_with_history(&history, &pair, &mut [0; 16]);
		if final_error {
			assert!(matches!(result, Err(HistoricalPreviewFailure::Live(_))));
		} else {
			assert!(matches!(
				result,
				Err(HistoricalPreviewFailure::ScopeMismatch)
			));
		}
		assert_eq!(
			*trace.borrow(),
			["initial_scope", "read_left", "read_right", "final_scope"]
		);
	}
}
