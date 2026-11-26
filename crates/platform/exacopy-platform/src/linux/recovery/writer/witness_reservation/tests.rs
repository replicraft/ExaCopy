use std::cell::RefCell;
use std::fs;
use std::io::{Seek as _, Write as _};
use std::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;
use exacopy_model::retained_prefix::Head;
use rustix::io::Errno;

use crate::linux::{DestinationRoot, FileIdentity};
use crate::scratch::Scratch;

use super::{
	Effect, HeldFirstSegment, PhantomData, Read as _, ReservedJournalRead, StageError,
	WitnessReservationAuthority, WitnessReservationError, WitnessReservationGateRequest,
	WitnessReservationPlan, native, submit,
};

const LIMIT: u64 = 64 * 1024 * 1024;
const HEAD: Head = Head {
	digest: [0x42; 32],
	sequence: 7,
	end: 24,
};

#[test]
fn allocation_may_refresh_write_times_but_not_other_selected_fields() {
	let scratch = Scratch::new();
	let file = std::fs::File::create(scratch.path("metadata-transition")).unwrap();
	let original = rustix::fs::fstat(&file).unwrap();
	let before = crate::linux::SourceObservation::capture(&original).unwrap();
	let mut refreshed = original;
	refreshed.st_mtime = original.st_mtime.checked_add(1).unwrap();
	refreshed.st_ctime = original.st_ctime.checked_add(1).unwrap();
	let after = crate::linux::SourceObservation::capture(&refreshed).unwrap();
	assert_ne!(before.modified_at(), after.modified_at());
	assert_ne!(before.changed_at(), after.changed_at());
	native::check_after_allocation(before, after).unwrap();
	let changes: [fn(&mut rustix::fs::Stat); 8] = [
		|stat| stat.st_ino ^= 1,
		|stat| stat.st_dev ^= 1,
		|stat| stat.st_size = 1,
		|stat| stat.st_mode ^= 0o100,
		|stat| stat.st_uid ^= 1,
		|stat| stat.st_gid ^= 1,
		|stat| stat.st_nlink ^= 1,
		|stat| stat.st_atime = stat.st_atime.checked_add(1).unwrap(),
	];
	for change in changes {
		let mut changed = refreshed;
		change(&mut changed);
		let changed = crate::linux::SourceObservation::capture(&changed).unwrap();
		assert!(matches!(
			native::check_after_allocation(before, changed),
			Err(StageError::IdentityChanged)
		));
	}
}

#[test]
fn native_plan_checks_the_positive_byte_and_sequence_bounds() {
	let frames = NonZeroU64::new(10).unwrap();
	let exact = WitnessReservationPlan::new(HEAD, LIMIT, frames).unwrap();
	assert_eq!(exact.accepted(), HEAD);
	assert_eq!(exact.reserve_end(), LIMIT);
	assert_eq!(exact.reserve_frames(), frames);
	assert_eq!(exact.allocation(), (24, LIMIT - 24));

	for (head, bound) in [
		(HEAD, LIMIT + 1),
		(HEAD, HEAD.end),
		(HEAD, HEAD.end - 1),
		(Head { end: 0, ..HEAD }, LIMIT),
		(
			Head {
				sequence: 0,
				..HEAD
			},
			LIMIT,
		),
		(
			Head {
				digest: [0; 32],
				..HEAD
			},
			LIMIT,
		),
		(
			Head {
				sequence: u64::MAX - 9,
				..HEAD
			},
			LIMIT,
		),
	] {
		assert!(matches!(
			WitnessReservationPlan::new(head, bound, frames),
			Err(WitnessReservationError::Bounds)
		));
	}
	assert!(
		WitnessReservationPlan::new(
			Head {
				sequence: u64::MAX - 10,
				..HEAD
			},
			LIMIT,
			frames,
		)
		.is_ok()
	);
}

#[derive(Debug, PartialEq, Eq)]
enum Event {
	Enter(Effect),
	Effect(Effect),
	Exit(Effect),
}

struct Guard<'a> {
	events: &'a RefCell<Vec<Event>>,
	effect: Effect,
}

impl Drop for Guard<'_> {
	fn drop(&mut self) {
		self.events.borrow_mut().push(Event::Exit(self.effect));
	}
}

#[test]
fn separate_gate_holds_through_syscall_and_refusal_runs_no_effect() {
	let scratch = Scratch::new();
	let identity = FileIdentity::from_stat(&rustix::fs::fstat(scratch.open()).unwrap());
	let events = RefCell::new(Vec::new());
	let mut original = request(identity, Effect::ReceiptCreate);
	original.plan =
		WitnessReservationPlan::new(HEAD, HEAD.end + 7_138, NonZeroU64::new(10).unwrap()).unwrap();
	original.authority = WitnessReservationAuthority {
		qualification: [0x34; 32],
		base_grant: [0xca; 32],
		retention_approval: [0x96; 32],
	};
	let mut gate = |request: WitnessReservationGateRequest<'_>| {
		assert_eq!(request.plan, original.plan);
		assert_eq!(request.authority, original.authority);
		events.borrow_mut().push(Event::Enter(request.effect));
		if request.effect == Effect::JournalAllocate {
			return Err("witness approval expired");
		}
		Ok(Guard {
			events: &events,
			effect: request.effect,
		})
	};
	for effect in [
		Effect::ReceiptCreate,
		Effect::ReceiptAllocate,
		Effect::JournalAllocate,
	] {
		let injected = if effect == Effect::ReceiptAllocate {
			Err(Errno::DQUOT)
		} else {
			Ok(())
		};
		let selected = WitnessReservationGateRequest {
			effect,
			receipt: (effect != Effect::ReceiptCreate).then_some(identity),
			..original
		};
		let result = submit(&mut gate, selected, || {
			events.borrow_mut().push(Event::Effect(effect));
			injected
		});
		match effect {
			Effect::ReceiptCreate => result.unwrap(),
			Effect::ReceiptAllocate => assert!(matches!(
				result,
				Err(WitnessReservationError::AfterEffect {
					effect: Effect::ReceiptAllocate,
					..
				})
			)),
			Effect::JournalAllocate => assert!(matches!(
				result,
				Err(WitnessReservationError::Gate {
					effect: Effect::JournalAllocate,
					source: "witness approval expired"
				})
			)),
		}
	}
	assert_eq!(
		events.into_inner(),
		vec![
			Event::Enter(Effect::ReceiptCreate),
			Event::Effect(Effect::ReceiptCreate),
			Event::Exit(Effect::ReceiptCreate),
			Event::Enter(Effect::ReceiptAllocate),
			Event::Effect(Effect::ReceiptAllocate),
			Event::Exit(Effect::ReceiptAllocate),
			Event::Enter(Effect::JournalAllocate),
		]
	);
}

fn request(identity: FileIdentity, effect: Effect) -> WitnessReservationGateRequest<'static> {
	WitnessReservationGateRequest {
		effect,
		authority: WitnessReservationAuthority {
			qualification: [1; 32],
			base_grant: [2; 32],
			retention_approval: [3; 32],
		},
		plan: WitnessReservationPlan::new(HEAD, LIMIT, NonZeroU64::MIN).unwrap(),
		destination: identity,
		job: identity,
		stage: super::RetainedPrefixSelection {
			stage: UnixComponent::new(b"stage").unwrap(),
			target: UnixComponent::new(b"target").unwrap(),
			directory: identity.into(),
			file: identity.into(),
		},
		journal_directory: identity,
		segment: identity,
		receipt: (effect != Effect::ReceiptCreate).then_some(identity),
	}
}

#[test]
#[ignore = "requires a task-owned Linux fixture supporting O_TMPFILE and KEEP_SIZE"]
fn native_allocation_preserves_the_named_segment_and_anonymous_eof() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"fixture-job").unwrap();
	let original = b"exact old journal bytes";
	let job = root.create_job_directory(name).unwrap();
	let directory = job.create_journal_directory().unwrap();
	let mut segment = directory.create_first_segment().unwrap();
	segment.write_all(original).unwrap();
	drop(segment);
	drop(directory);
	drop(job);
	let identity = root.open_recovery_job(name).unwrap().identity();
	let lease = root.try_recovery_write_lease(name, identity).unwrap();
	let expected = lease.job().open_first_segment().unwrap();
	let mut journal = lease.hold_first_segment_for_append(&expected).unwrap();
	let opened = journal.file.stream_position().unwrap();
	assert_eq!(opened, original.len() as u64);
	assert!(matches!(
		lease.open_first_segment_for_append(&expected),
		Err(StageError::JobBusy)
	));

	let parent = &lease.job().directory.file;
	let receipt = native::open_anonymous(parent).unwrap().into();
	let before = native::inspect_anonymous(&receipt, root.mount).unwrap();
	native::allocate(&receipt, 0, 6_144).unwrap();
	let after = native::inspect_anonymous(&receipt, root.mount).unwrap();
	eprintln!("anonymous allocation before={before:?} after={after:?}");
	native::check_after_allocation(before, after).unwrap();
	assert_eq!(
		fs::read_dir(scratch.path("fixture-job")).unwrap().count(),
		1
	);

	let request = test_journal_request(expected.identity(), opened);
	lease
		.submit_journal_allocation(&journal, &mut |_| Ok::<(), &'static str>(()), request)
		.unwrap();
	assert_eq!(journal.file.stream_position().unwrap(), opened);
	let readback = lease.job().open_first_segment().unwrap();
	native::check_after_allocation(expected.observation(), readback.observation()).unwrap();
	journal.recheck(&lease, &readback).unwrap();

	let mut cursor = ReservedJournalRead {
		readback: &readback,
		offset: 0,
		_same_lane: PhantomData,
	};
	let mut actual = Vec::new();
	cursor.read_to_end(&mut actual).unwrap();
	assert_eq!(actual, original);
	assert_eq!(cursor.read(&mut [0]).unwrap(), 0);
	journal.recheck(&lease, &readback).unwrap();
	drop_receipt_without_an_installed_name(receipt, &scratch);
	assert_named_change_refuses(journal, &lease, &readback, &scratch);
}

#[test]
#[ignore = "requires a task-owned Linux fixture supporting Linux recovery descriptors"]
fn only_a_submitted_journal_allocation_latches_the_lease_even_on_syscall_error() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"intentional-readonly").unwrap();
	let original = b"exact old journal bytes";
	let job = root.create_job_directory(name).unwrap();
	let directory = job.create_journal_directory().unwrap();
	let mut segment = directory.create_first_segment().unwrap();
	segment.write_all(original).unwrap();
	drop(segment);
	drop(directory);
	drop(job);
	let identity = root.open_recovery_job(name).unwrap().identity();
	let lease = root.try_recovery_write_lease(name, identity).unwrap();
	let expected = lease.job().open_first_segment().unwrap();
	let mut journal = lease.hold_first_segment_for_append(&expected).unwrap();
	let request = test_journal_request(expected.identity(), expected.len());
	let denied =
		lease.submit_journal_allocation(&journal, &mut |_| Err::<(), _>("denied"), request);
	assert!(matches!(denied, Err(WitnessReservationError::Gate { .. })));
	drop(journal);
	journal = lease.hold_first_segment_for_append(&expected).unwrap();

	// Force a deterministic kernel refusal on an owned read-only fixture inode.
	journal.file = std::fs::File::open(
		scratch
			.path("intentional-readonly")
			.join(super::JOURNAL)
			.join(super::FIRST_SEGMENT),
	)
	.unwrap();
	let failed =
		lease.submit_journal_allocation(&journal, &mut |_| Ok::<(), &'static str>(()), request);
	assert!(matches!(failed, Err(WitnessReservationError::AfterEffect {
		effect: Effect::JournalAllocate,
		source: super::WitnessReservationObservationError::Native(StageError::System(ref cause)),
	}) if cause.raw_os_error() == Some(Errno::BADF.raw_os_error())));
	drop(journal);
	assert!(matches!(
		lease.open_first_segment_for_append(&expected),
		Err(StageError::JobBusy)
	));
	let mut untouched = vec![0; original.len()];
	expected.read_exact_at(0, &mut untouched).unwrap();
	assert_eq!(untouched, original);
}

fn test_journal_request(
	identity: FileIdentity,
	end: u64,
) -> WitnessReservationGateRequest<'static> {
	let mut exact = request(identity, Effect::JournalAllocate);
	exact.plan = WitnessReservationPlan::new(
		Head { end, ..HEAD },
		end.checked_add(6_022).unwrap(),
		NonZeroU64::new(9).unwrap(),
	)
	.unwrap();
	exact
}

fn drop_receipt_without_an_installed_name(file: std::fs::File, scratch: &Scratch) {
	drop(file);
	assert_eq!(
		fs::read_dir(scratch.path("fixture-job")).unwrap().count(),
		1
	);
}

fn assert_named_change_refuses(
	journal: HeldFirstSegment<'_>,
	lease: &super::RecoveryWriteLease<'_>,
	readback: &super::RecoveryFile,
	scratch: &Scratch,
) {
	let path = scratch
		.path("fixture-job")
		.join(super::JOURNAL)
		.join(super::FIRST_SEGMENT);
	let moved = scratch.path("moved-test-record");
	fs::rename(&path, &moved).unwrap();
	assert!(journal.recheck(lease, readback).is_err());
	assert!(!path.exists());
	assert_eq!(fs::read(moved).unwrap(), b"exact old journal bytes");
}
