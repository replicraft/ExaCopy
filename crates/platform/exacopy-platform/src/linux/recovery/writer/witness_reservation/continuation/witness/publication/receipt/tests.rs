use std::num::NonZeroU64;
use std::os::unix::fs::FileExt as _;

use exacopy_model::retained_prefix::Head;
use rustix::fs;

use super::super::super::super::super::native::{allocate, inspect_anonymous, open_anonymous};
use super::native::{
	confirm_transition, exact_receipt, link_pending, pin_receipt_name, rename_pending,
	reopen_sealed, require_absent,
};
use super::{
	MAX_COMMITTED, MAX_READY, RECEIPT_CAPACITY, WitnessReceiptAppend, WitnessReceiptNames,
	WitnessReservationPlan, matches_bounds, matches_names,
};
use crate::linux::recovery::mount_id;
use crate::linux::{StageError, WitnessCredentialLane};
use crate::scratch::Scratch;

const NAMES: WitnessReceiptNames = WitnessReceiptNames {
	pending: *b"rw-receipt.pending.0102030405060708090a0b0c0d0e0f10.0000000000000001.1112131415161718191a1b1c1d1e1f20",
	final_name: *b"rw-receipt.final.0102030405060708090a0b0c0d0e0f10.0000000000000001.1112131415161718191a1b1c1d1e1f20",
};
const WITNESS: &[u8; 40] = b"witness.1112131415161718191a1b1c1d1e1f20";

#[test]
fn projected_ready_leaves_exact_full_terminal_reservation_and_slot() {
	let prior = Head {
		digest: [1; 32],
		sequence: 8,
		end: 1990,
	};
	let ready = Head {
		digest: [2; 32],
		sequence: 9,
		end: prior.end + MAX_READY as u64,
	};
	let committed = Head {
		digest: [3; 32],
		sequence: 10,
		end: ready.end + MAX_COMMITTED as u64,
	};
	let ready_frame = WitnessReceiptAppend {
		previous: prior,
		successor: ready,
		encoded: vec![0; MAX_READY],
	};
	let commit_frame = WitnessReceiptAppend {
		previous: ready,
		successor: committed,
		encoded: vec![0; MAX_COMMITTED],
	};
	let plan = |end, slots| {
		WitnessReservationPlan::new(prior, end, NonZeroU64::new(slots).unwrap()).unwrap()
	};
	assert!(matches_bounds(
		plan(committed.end, 2),
		prior,
		&ready_frame,
		true
	));
	assert!(matches_bounds(
		plan(committed.end, 2),
		ready,
		&commit_frame,
		false
	));
	assert!(!matches_bounds(
		plan(committed.end - 1, 2),
		prior,
		&ready_frame,
		true
	));
	assert!(!matches_bounds(
		plan(committed.end, 1),
		prior,
		&ready_frame,
		true
	));
	assert!(!matches_bounds(
		plan(committed.end, 2),
		prior,
		&commit_frame,
		false
	));
}

#[test]
fn receipt_names_keep_exact_pair_and_original_witness_nonce() {
	assert!(matches_names(&NAMES, WITNESS));
	let mut wrong = NAMES;
	wrong.pending[19] = b'/';
	assert!(!matches_names(&wrong, WITNESS));
	let mut wrong_witness = *WITNESS;
	wrong_witness[8] = b'2';
	assert!(!matches_names(&NAMES, &wrong_witness));
}

#[test]
#[ignore = "requires a task-owned unprivileged Linux fixture with reopened descriptor AT_EMPTY_PATH"]
fn readonly_reopened_anonymous_receipt_links_and_promotes_original_inode() {
	let scratch = Scratch::new();
	let job = scratch.open();
	let mount = mount_id(&job).unwrap();
	let lane = WitnessCredentialLane::observe().unwrap();
	let bytes = b"literal component receipt bytes";
	let writable = open_anonymous(&job).unwrap().into();
	let original = inspect_anonymous(&writable, mount).unwrap();
	allocate(&writable, 0, RECEIPT_CAPACITY).unwrap();
	assert_eq!(writable.write_at(bytes, 0).unwrap(), bytes.len());
	fs::fsync(&writable).unwrap();

	lane.recheck().unwrap();
	let (readonly, sealed) = reopen_sealed(&writable, original, bytes, mount).unwrap();
	drop(writable);
	assert_eq!(
		fs::fcntl_getfl(&readonly)
			.unwrap()
			.intersection(fs::OFlags::ACCMODE),
		fs::OFlags::RDONLY
	);
	assert_eq!(sealed.identity(), original.identity());
	assert_eq!(sealed.link_count(), 0);
	assert_eq!(sealed.len(), bytes.len() as u64);

	require_absent(&job, &NAMES).unwrap();
	lane.recheck().unwrap();
	link_pending(&readonly, &job, &NAMES).unwrap();
	let pending = exact_receipt(&readonly, sealed, bytes, 1, mount).unwrap();
	confirm_transition(sealed, pending).unwrap();
	let _pending = pin_receipt_name(&job, mount, pending, &NAMES, false).unwrap();
	fs::fsync(&readonly).unwrap();
	fs::fsync(&job).unwrap();
	let pending_after_barriers = exact_receipt(&readonly, original, bytes, 1, mount).unwrap();
	pending.recheck(pending_after_barriers).unwrap();
	let _pending = pin_receipt_name(&job, mount, pending_after_barriers, &NAMES, false).unwrap();

	// Exercise the raw no-replace primitive with controlled occupancy. The
	// application capability does not repeat an attempted promotion.
	let incumbent = scratch.path(std::str::from_utf8(&NAMES.final_name).unwrap());
	std::fs::write(&incumbent, b"independent incumbent").unwrap();
	assert!(matches!(
		rename_pending(&job, &NAMES),
		Err(StageError::System(cause)) if cause.raw_os_error() == Some(rustix::io::Errno::EXIST.raw_os_error())
	));
	let pending_after_conflict = exact_receipt(&readonly, original, bytes, 1, mount).unwrap();
	pending.recheck(pending_after_conflict).unwrap();
	assert_eq!(std::fs::read(&incumbent).unwrap(), b"independent incumbent");
	std::fs::remove_file(incumbent).unwrap();
	let _pending = pin_receipt_name(&job, mount, pending, &NAMES, false).unwrap();
	lane.recheck().unwrap();
	rename_pending(&job, &NAMES).unwrap();
	let final_receipt = exact_receipt(&readonly, pending, bytes, 1, mount).unwrap();
	confirm_transition(pending, final_receipt).unwrap();
	let _final = pin_receipt_name(&job, mount, final_receipt, &NAMES, true).unwrap();
	assert_eq!(final_receipt.identity(), original.identity());
	fs::fsync(&readonly).unwrap();
	fs::fsync(&job).unwrap();
	let final_after_barriers = exact_receipt(&readonly, original, bytes, 1, mount).unwrap();
	final_receipt.recheck(final_after_barriers).unwrap();
	let _final = pin_receipt_name(&job, mount, final_after_barriers, &NAMES, true).unwrap();
}
