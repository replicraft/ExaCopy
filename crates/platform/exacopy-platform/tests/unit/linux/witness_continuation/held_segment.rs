use std::cell::Cell;
use std::io::{Read as _, Write as _};
use std::marker::PhantomData;

use exacopy_endpoint::UnixComponent;

use crate::linux::DestinationRoot;
use crate::scratch::Scratch;

use super::super::{
	ReservedJournalRead, StageError, WitnessReservationObservationError, append_held,
	observe_successor,
};

struct AdmissionGuard<'a>(&'a Cell<bool>);

impl Drop for AdmissionGuard<'_> {
	fn drop(&mut self) {
		self.0.set(true);
	}
}

#[test]
fn submitted_frame_survives_refused_readback_and_replays_from_the_original_inode() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"continued-readback").unwrap();
	let prior = b"verified prefix";
	let submitted = b"submitted successor";
	{
		let job = root.create_job_directory(name).unwrap();
		let directory = job.create_journal_directory().unwrap();
		let mut segment = directory.create_first_segment().unwrap();
		segment.write_all(prior).unwrap();
	}

	let identity = root.open_recovery_job(name).unwrap().identity();
	let lease = root.try_recovery_write_lease(name, identity).unwrap();
	let previous = lease.job().open_first_segment().unwrap();
	let mut held = lease.hold_first_segment_for_append(&previous).unwrap();
	let released = Cell::new(false);
	append_held(&mut held, submitted, AdmissionGuard(&released)).unwrap();
	assert!(
		released.get(),
		"the submission guard must be released before read-back"
	);

	let start = u64::try_from(prior.len()).unwrap();
	let end = start + u64::try_from(submitted.len()).unwrap();
	let mut wrong_bytes = *submitted;
	wrong_bytes[0] ^= 1;
	for (claimed_end, claimed_bytes) in [(end - 1, submitted), (end, &wrong_bytes)] {
		assert!(matches!(
			observe_successor(&held, &lease, &previous, start, claimed_end, claimed_bytes),
			Err(WitnessReservationObservationError::Native(
				StageError::IdentityChanged
			))
		));
	}

	let accepted = observe_successor(&held, &lease, &previous, start, end, submitted).unwrap();
	assert_eq!(accepted.identity(), previous.identity());
	let mut cursor = ReservedJournalRead {
		readback: &accepted,
		offset: 0,
		_same_lane: PhantomData,
	};
	let mut bytes = Vec::new();
	cursor.read_to_end(&mut bytes).unwrap();
	assert_eq!(bytes, [prior.as_slice(), submitted.as_slice()].concat());
	assert_eq!(cursor.read(&mut [0]).unwrap(), 0);
}
