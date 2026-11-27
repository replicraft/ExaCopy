use std::error::Error as _;
use std::io::{self, Read as _, Write as _};
use std::marker::PhantomData;

use exacopy_endpoint::UnixComponent;

use crate::linux::{
	DestinationRoot, ReadError, RecoveryFile, RecoveryWriteLease,
	RemoteDestinationEligibilityError, StageError,
};
use crate::scratch::Scratch;

use super::super::{
	Effect, FIRST_SEGMENT, JOURNAL, ReservedJournalRead, WitnessReservationError,
	WitnessReservationObservationError, native,
};

const JOB: &str = "reservation-observations";
const OLD_BYTES: &[u8; 8] = b"old head";

struct JournalFixture {
	root: DestinationRoot,
	scratch: Scratch,
}

impl JournalFixture {
	fn new(bytes: &[u8]) -> Self {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let name = UnixComponent::new(JOB.as_bytes()).unwrap();
		{
			let job = root.create_job_directory(name).unwrap();
			let directory = job.create_journal_directory().unwrap();
			let mut segment = directory.create_first_segment().unwrap();
			segment.write_all(bytes).unwrap();
		}
		Self { root, scratch }
	}

	fn lease(&self) -> RecoveryWriteLease<'_> {
		let name = UnixComponent::new(JOB.as_bytes()).unwrap();
		let job = self.root.open_recovery_job(name).unwrap();
		self.root
			.try_recovery_write_lease(name, job.identity())
			.unwrap()
	}

	fn segment_bytes(&self) -> Vec<u8> {
		std::fs::read(self.scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT)).unwrap()
	}
}

fn cursor(readback: &RecoveryFile) -> ReservedJournalRead<'_> {
	ReservedJournalRead {
		readback,
		offset: 0,
		_same_lane: PhantomData,
	}
}

#[test]
fn journal_apertures_keep_independent_offsets_and_refuse_a_grown_eof() {
	let fixture = JournalFixture::new(OLD_BYTES);
	let lease = fixture.lease();
	let readback = lease.job().open_first_segment().unwrap();
	let mut held = lease.hold_first_segment_for_append(&readback).unwrap();
	let mut first = cursor(&readback);
	let mut second = cursor(&readback);

	assert_eq!(first.read(&mut []).unwrap(), 0, "empty buffer before EOF");
	let mut prefix = [0; 3];
	first.read_exact(&mut prefix).unwrap();
	assert_eq!(&prefix, b"old", "first aperture begins at byte zero");
	let mut all = [0; OLD_BYTES.len()];
	second.read_exact(&mut all).unwrap();
	assert_eq!(&all, OLD_BYTES, "second aperture starts independently");

	let mut rest = [0xff; OLD_BYTES.len()];
	assert_eq!(
		first.read(&mut rest).unwrap(),
		5,
		"read stops at admitted EOF"
	);
	assert_eq!(&rest[..5], b" head");
	assert_eq!(&rest[5..], &[0xff; 3], "rest of the buffer stays untouched");
	assert_eq!(first.read(&mut rest).unwrap(), 0, "unchanged EOF");
	held.recheck(&lease, &readback).unwrap();

	// Append one byte only to the owned fixture to exercise the stale EOF probe.
	held.file.write_all(b"!").unwrap();
	let error = second.read(&mut []).unwrap_err();
	assert_eq!(error.kind(), io::ErrorKind::Other);
	assert!(matches!(
		error
			.get_ref()
			.and_then(|cause| cause.downcast_ref::<ReadError>()),
		Some(ReadError::UnexpectedDataAfterEnd)
	));
	assert!(matches!(
		held.recheck(&lease, &readback),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fixture.segment_bytes(), b"old head!");
}

#[test]
fn anonymous_receipt_inspection_refuses_a_named_empty_private_record() {
	let fixture = JournalFixture::new(b"");
	let lease = fixture.lease();
	let expected = lease.job().open_first_segment().unwrap();
	let held = lease.hold_first_segment_for_append(&expected).unwrap();
	assert!(matches!(
		native::inspect_anonymous(&held.file, fixture.root.mount),
		Err(StageError::UnsafeFile)
	));
	held.recheck(&lease, &expected).unwrap();
	assert!(fixture.segment_bytes().is_empty());
}

#[test]
fn reservation_errors_keep_the_refusal_phase_and_typed_cause() {
	let preflight: WitnessReservationError =
		WitnessReservationError::Preflight(RemoteDestinationEligibilityError::DifferentRoot.into());
	assert!(
		preflight
			.to_string()
			.starts_with("reservation preflight refused")
	);
	let observation = preflight
		.source()
		.and_then(|cause| cause.downcast_ref::<WitnessReservationObservationError>())
		.expect("preflight carries an observation error");
	assert!(matches!(
		observation
			.source()
			.and_then(|cause| cause.downcast_ref::<RemoteDestinationEligibilityError>()),
		Some(RemoteDestinationEligibilityError::DifferentRoot)
	));

	let uncertain: WitnessReservationError =
		WitnessReservationError::after(Effect::JournalAllocate, StageError::IdentityChanged);
	assert!(
		uncertain
			.to_string()
			.starts_with("reservation failed after submitting JournalAllocate")
	);
	let observation = uncertain
		.source()
		.and_then(|cause| cause.downcast_ref::<WitnessReservationObservationError>())
		.expect("reconciliation carries an observation error");
	assert!(matches!(
		observation
			.source()
			.and_then(|cause| cause.downcast_ref::<StageError>()),
		Some(StageError::IdentityChanged)
	));
}
