use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};

use super::{RANDOM_STAGE_ID_BYTES, StageBindingContext, StageError};

const TEST_ENTROPY: [u8; RANDOM_STAGE_ID_BYTES] = [0xB7; RANDOM_STAGE_ID_BYTES];

#[test]
fn repeating_entropy_still_allocates_distinct_bindings_for_one_context() {
	let mut job_bytes = [0; 16];
	job_bytes[6] = 0x70;
	job_bytes[8] = 0x80;
	let job = JobId::try_from_bytes(job_bytes).expect("fixture UUIDv7");
	let entry = EntryId::new(7);
	let epoch = RunEpoch::new(13);
	let context = StageBindingContext::new(job, entry, epoch);
	let serial = AtomicU32::new(0);
	let entropy = |bytes: &mut [u8; RANDOM_STAGE_ID_BYTES]| {
		*bytes = TEST_ENTROPY;
		Ok(())
	};
	let first = context.allocate_with_serial(&serial, entropy).unwrap();
	let second = context.allocate_with_serial(&serial, entropy).unwrap();

	for identity in [first, second] {
		assert_eq!(
			&identity.stage_id_bytes()[..RANDOM_STAGE_ID_BYTES],
			&TEST_ENTROPY
		);
		assert_eq!(
			identity.binding(),
			CopyBinding::new(
				job,
				entry,
				epoch,
				StageId::from_bytes(*identity.stage_id_bytes())
			)
		);
	}
	assert_ne!(first.binding(), second.binding());
}

#[test]
fn serial_exhaustion_is_permanent_and_never_wraps() {
	let context = super::super::tests::context();
	let serial = AtomicU32::new(u32::MAX - 1);
	assert!(context.allocate_with_serial(&serial, |_| Ok(())).is_ok());
	assert!(matches!(
		context.allocate_with_serial(&serial, |_| Ok(())),
		Err(StageError::StageIdsExhausted)
	));
	assert!(matches!(
		context.allocate_with_serial(&serial, |_| Ok(())),
		Err(StageError::StageIdsExhausted)
	));
	assert_eq!(serial.load(Ordering::Relaxed), u32::MAX);
}

#[test]
fn entropy_failure_does_not_allocate_an_attempt_identity() {
	let context = super::super::tests::context();
	let serial = AtomicU32::new(0);
	let error = context
		.allocate_with_serial(&serial, |bytes| {
			bytes[0] = TEST_ENTROPY[0];
			Err(io::Error::from_raw_os_error(libc::EIO))
		})
		.unwrap_err();
	assert!(
		matches!(error, StageError::EntropyUnavailable(error) if error.raw_os_error() == Some(libc::EIO))
	);
	assert_eq!(serial.load(Ordering::Relaxed), 0);
}
