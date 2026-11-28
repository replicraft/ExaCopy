use std::cell::Cell;
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt as _;

use exacopy_endpoint::linux_remote_qualification::RemoteDestinationQualification;
use exacopy_endpoint::{ReadView as _, UnixComponent};
use exacopy_model::retained_prefix::Head;

use crate::linux::job::{FIRST_SEGMENT, JOURNAL, STAGE};
use crate::linux::{
	DestinationRoot, RemoteDestinationEligibility, RetainedPrefixSelection, StageError, SuffixEffect,
	WitnessReservationAuthority, WitnessReservationEffect, WitnessReservationPlan,
	observe_remote_destination,
};
use crate::scratch::Scratch;

use super::super::{ReservedJournalRead, native};
use super::{ContinuationReservationError, append_held, observe_successor};

#[path = "../../../../../../tests/unit/linux/witness_continuation/bounds.rs"]
mod bounds;
#[path = "../../../../../../tests/unit/linux/witness_continuation/held_segment.rs"]
mod held_segment;

#[test]
#[ignore = "requires a task-owned ext4 fixture with O_TMPFILE and KEEP_SIZE"]
fn original_reserved_descriptor_writes_and_rereads_only_the_exact_successor() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"continued-custody").unwrap();
	let old = b"authenticated prior transcript";
	let successor = b"one bounded canonical transition supplied by application";
	let job = root.create_job_directory(name).unwrap();
	let directory = job.create_journal_directory().unwrap();
	let mut segment = directory.create_first_segment().unwrap();
	segment.write_all(old).unwrap();
	drop(segment);
	drop(directory);
	drop(job);

	let id = root.open_recovery_job(name).unwrap().identity();
	let lease = root.try_recovery_write_lease(name, id).unwrap();
	let expected = lease.job().open_first_segment().unwrap();
	let mut held = lease.hold_first_segment_for_append(&expected).unwrap();
	let descriptor = std::os::fd::AsRawFd::as_raw_fd(&held.file);
	native::allocate(&held.file, expected.len(), 8_192).unwrap();
	let expected = lease.job().open_first_segment().unwrap();
	held.recheck(&lease, &expected).unwrap();
	assert!(lease.open_first_segment_for_append(&expected).is_err());

	append_held(&mut held, successor, ()).unwrap();
	let end = expected.len() + successor.len() as u64;
	assert_eq!(std::os::fd::AsRawFd::as_raw_fd(&held.file), descriptor);
	assert!(
		observe_successor(&held, &lease, &expected, expected.len(), end - 1, successor).is_err()
	);
	let mut incorrect = successor.to_vec();
	incorrect[0] ^= 1;
	assert!(observe_successor(&held, &lease, &expected, expected.len(), end, &incorrect).is_err());
	let accepted =
		observe_successor(&held, &lease, &expected, expected.len(), end, successor).unwrap();
	assert_eq!(accepted.identity(), expected.identity());
	let mut readback = ReservedJournalRead {
		readback: &accepted,
		offset: 0,
		_same_lane: std::marker::PhantomData,
	};
	let mut bytes = Vec::new();
	readback.read_to_end(&mut bytes).unwrap();
	assert_eq!(&bytes[..old.len()], old);
	assert_eq!(&bytes[old.len()..], successor);
	assert_eq!(readback.read(&mut [0]).unwrap(), 0);

	refused_live_continuation_retains_the_original_prefix_and_journal();
}

fn refused_live_continuation_retains_the_original_prefix_and_journal() {
	#[derive(Debug, Eq, PartialEq)]
	enum Refusal {
		Expired,
	}

	const JOB: &str = "continuation-gate";
	const PART: &str = "retained-part";
	const TARGET: &str = "public-target";
	const PREVIOUS: &[u8] = b"prior accepted transcript";
	const PREFIX: &[u8] = b"retained file bytes";
	const CANDIDATE: &[u8] = b"proposed bounded frame";

	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = |name: &'static str| UnixComponent::new(name.as_bytes()).unwrap();
	let stage_path = scratch.path(JOB).join(STAGE).join(PART);
	{
		let job = root.create_job_directory(name(JOB)).unwrap();
		job.create_stage_directory().unwrap();
		fs::write(&stage_path, PREFIX).unwrap();
		fs::set_permissions(&stage_path, fs::Permissions::from_mode(0o600)).unwrap();
		let directory = job.create_journal_directory().unwrap();
		let mut segment = directory.create_first_segment().unwrap();
		segment.write_all(PREVIOUS).unwrap();
	}

	// Match the real held ext4 facts. The digest, source replay and authority
	// callbacks are fixture inputs at the platform boundary.
	let qualification = RemoteDestinationQualification::new(
		observe_remote_destination(&root).unwrap(),
		[0x35; 32],
	)
	.unwrap();
	let eligible = RemoteDestinationEligibility::admit(&root, Some(&qualification)).unwrap();
	let job_id = root.open_recovery_job(name(JOB)).unwrap().identity();
	let lease = root.try_recovery_write_lease(name(JOB), job_id).unwrap();
	let job = lease.job();
	let expected = job.open_first_segment().unwrap();
	let inventory = job.inventory(name(PART), name(TARGET)).unwrap();
	let selection = RetainedPrefixSelection {
		stage: name(PART),
		target: name(TARGET),
		directory: inventory.stage_directory_identity().unwrap().into(),
		file: inventory.stage().unwrap().identity().into(),
	};
	let stage = lease.read_retained_prefix(&inventory, selection).unwrap();
	let staged_extent = stage.length();
	assert_eq!(staged_extent, PREFIX.len() as u64);
	let before = Head {
		sequence: 4,
		digest: [0x42; 32],
		end: PREVIOUS.len() as u64,
	};
	let after = Head {
		sequence: 5,
		digest: [0x61; 32],
		end: before.end + CANDIDATE.len() as u64,
	};
	let rows = NonZeroU64::new(2).unwrap();
	let plan = WitnessReservationPlan::new(before, before.end + 8_192, rows).unwrap();
	let authority = WitnessReservationAuthority {
		qualification: qualification.digest(),
		base_grant: [0x79; 32],
		retention_approval: [0x80; 32],
	};
	let mut effects = Vec::new();
	let mut reserved_objects = None;
	let pending = lease
		.reserve_witness_closeout(&eligible, &stage, &expected, plan, authority, |request| {
			effects.push(request.effect);
			if request.effect == WitnessReservationEffect::JournalAllocate {
				reserved_objects = Some((request.journal_directory, request.receipt.unwrap()));
			}
			Ok::<_, Refusal>(())
		})
		.unwrap();
	assert_eq!(
		effects,
		[
			WitnessReservationEffect::ReceiptCreate,
			WitnessReservationEffect::ReceiptAllocate,
			WitnessReservationEffect::JournalAllocate,
		]
	);
	let (journal_directory, receipt) = reserved_objects.unwrap();
	let prefix = stage
		.sync_adopted(staged_extent, |actual, effect| {
			assert_eq!(actual, selection);
			assert_eq!(effect, SuffixEffect::PrefixBarrier { end: staged_extent });
			Ok::<_, Refusal>(())
		})
		.unwrap();

	let replay_completed = Cell::new(false);
	let result = pending.append_continuation(
		&prefix,
		after,
		CANDIDATE,
		|mut candidate| {
			let mut observed = Vec::new();
			candidate.read_to_end(&mut observed).unwrap();
			assert_eq!(observed, PREVIOUS);
			assert!(!replay_completed.replace(true));
			Ok(())
		},
		|request| {
			assert!(
				replay_completed.get(),
				"the gate requires successful prior byte replay"
			);
			assert_eq!(request.previous, before);
			assert_eq!(request.successor, after);
			assert_eq!(request.authority, authority);
			assert_eq!(request.plan, plan);
			assert_eq!(request.destination, root.identity());
			assert_eq!(request.job, job_id);
			assert_eq!(request.stage, selection);
			assert_eq!(request.segment, expected.identity());
			assert_eq!(request.journal_directory, journal_directory);
			assert_eq!(request.receipt, receipt);
			Err::<(), _>(Refusal::Expired)
		},
		|_| panic!("refused native append must not invoke successor verification"),
	);
	assert!(matches!(
		result,
		Err(ContinuationReservationError::Admission(Refusal::Expired))
	));
	let retained = job.open_first_segment().unwrap();
	assert_eq!(retained.identity(), expected.identity());
	assert_eq!(retained.len(), before.end);
	assert_eq!(
		fs::read(scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT)).unwrap(),
		PREVIOUS
	);
	assert_eq!(fs::read(stage_path).unwrap(), PREFIX);
	assert_eq!(
		fs::symlink_metadata(scratch.path(TARGET)).unwrap_err().kind(),
		ErrorKind::NotFound
	);
	assert!(matches!(
		lease.open_first_segment_for_append(&retained),
		Err(StageError::JobBusy)
	));
}
