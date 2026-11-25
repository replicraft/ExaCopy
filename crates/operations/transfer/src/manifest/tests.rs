use std::cell::{Cell, RefCell};

use exacopy_content::{MAX_SCRATCH_BYTES, StreamInputError};
use exacopy_endpoint::MAX_FILE_LENGTH;

use super::{
	Error, MeasureError, Measurement, ReadView, SingleFileManifest, VerifyDecision, measure, verify,
};

const INPUT: &[u8] = b"abc";
const DIGEST: [u8; 32] = [
	0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
	0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
];
const EMPTY_DIGEST: [u8; 32] = [
	0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
	0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];
const OBSERVED: Measurement = Measurement {
	length: 3,
	digest: DIGEST,
};

#[test]
fn measurement_bounds_reads_and_checks_observations_in_order() {
	let view = View::new(INPUT);
	assert_eq!(measure(&view, &mut [0; 2]).unwrap(), OBSERVED);
	assert_eq!(
		*view.steps.borrow(),
		[Step::Check, Step::Read(0, 2), Step::Read(2, 1), Step::Check]
	);
}

#[test]
fn empty_stream_is_verified_without_a_payload_read() {
	let view = View::new(b"");
	let expected = baseline(0, EMPTY_DIGEST);
	assert_eq!(
		verify(&view, &expected, &mut []).unwrap(),
		VerifyDecision::Match(Measurement {
			length: 0,
			digest: EMPTY_DIGEST
		})
	);
	assert_eq!(*view.steps.borrow(), [Step::Check, Step::Check]);
}

#[test]
fn bounds_fail_before_any_observation_or_payload_read() {
	let mut view = View::new(INPUT);
	view.length = MAX_FILE_LENGTH + 1;
	assert!(matches!(
		measure(&view, &mut [0; 1]),
		Err(Error::Measure(MeasureError::InvalidInput(
			StreamInputError::FileTooLong { .. }
		)))
	));
	view.length = 3;
	assert!(matches!(
		measure(&view, &mut []),
		Err(Error::Measure(MeasureError::InvalidInput(
			StreamInputError::EmptyScratch
		)))
	));
	assert!(matches!(
		measure(&view, &mut vec![0; MAX_SCRATCH_BYTES + 1]),
		Err(Error::Measure(MeasureError::InvalidInput(
			StreamInputError::ScratchTooLarge { .. }
		)))
	));
	assert!(view.steps.borrow().is_empty());
}

#[test]
fn first_observation_and_failed_read_stop_at_their_respective_boundaries() {
	let initial = View {
		fault: Some(Fault::Initial),
		..View::new(INPUT)
	};
	assert!(matches!(
		measure(&initial, &mut [0; 2]),
		Err(Error::InitialObservation(Fault::Initial))
	));
	assert_eq!(*initial.steps.borrow(), [Step::Check]);

	let read = View {
		fault: Some(Fault::Read),
		..View::new(INPUT)
	};
	assert!(matches!(
		measure(&read, &mut [0; 2]),
		Err(Error::Measure(MeasureError::Read {
			offset: 0,
			source: Fault::Read
		}))
	));
	assert_eq!(*read.steps.borrow(), [Step::Check, Step::Read(0, 2)]);
}

#[test]
fn compares_length_then_digest_only_after_final_observation() {
	for (stored_length, stored_digest, want) in [
		(3, DIGEST, VerifyDecision::Match(OBSERVED)),
		(2, [0; 32], VerifyDecision::LengthMismatch(OBSERVED)),
		(3, [0; 32], VerifyDecision::DigestMismatch(OBSERVED)),
	] {
		let expected = baseline(stored_length, stored_digest);
		let checked = View::new(INPUT);
		assert_eq!(verify(&checked, &expected, &mut [0; 2]).unwrap(), want);

		let changed = View {
			fault: Some(Fault::Final),
			..View::new(INPUT)
		};
		assert!(matches!(
			verify(&changed, &expected, &mut [0; 2]),
			Err(Error::FinalObservation(Fault::Final))
		));
		assert_eq!(
			*changed.steps.borrow(),
			[Step::Check, Step::Read(0, 2), Step::Read(2, 1), Step::Check]
		);
	}
}

fn baseline(length: u64, digest: [u8; 32]) -> SingleFileManifest {
	SingleFileManifest::new(
		"019a0000-0000-7000-8000-000000000002".parse().unwrap(),
		"019a0000-0000-7000-8000-000000000003".parse().unwrap(),
		b"source",
		length,
		digest,
	)
	.unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
	Initial,
	Read,
	Final,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
	Check,
	Read(u64, usize),
}

struct View<'a> {
	bytes: &'a [u8],
	length: u64,
	fault: Option<Fault>,
	checks: Cell<u8>,
	steps: RefCell<Vec<Step>>,
}

impl<'a> View<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self {
			bytes,
			length: u64::try_from(bytes.len()).unwrap(),
			fault: None,
			checks: Cell::new(0),
			steps: RefCell::new(Vec::new()),
		}
	}
}

impl ReadView for View<'_> {
	type Error = Fault;

	fn length(&self) -> u64 {
		self.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.steps.borrow_mut().push(Step::Check);
		let check = self.checks.get();
		self.checks.set(check + 1);
		match (check, self.fault) {
			(0, Some(Fault::Initial)) => Err(Fault::Initial),
			(1, Some(Fault::Final)) => Err(Fault::Final),
			_ => Ok(()),
		}
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.steps
			.borrow_mut()
			.push(Step::Read(offset, buffer.len()));
		if self.fault == Some(Fault::Read) {
			return Err(Fault::Read);
		}
		let start = usize::try_from(offset).unwrap();
		let end = start.checked_add(buffer.len()).unwrap();
		buffer.copy_from_slice(&self.bytes[start..end]);
		Ok(())
	}
}
