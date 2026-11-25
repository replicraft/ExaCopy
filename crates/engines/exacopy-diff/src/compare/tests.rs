use std::cell::{Cell, RefCell};
use std::io::{self, ErrorKind};

use exacopy_endpoint::{MAX_FILE_LENGTH, ReadView};

use crate::{CompareError, Difference, LiveComparison, MAX_SCRATCH_BYTES, Side, compare};

struct View<'a> {
	bytes: &'a [u8],
	length: u64,
	reads: RefCell<Vec<(u64, usize)>>,
	checks: Cell<usize>,
	fail_check: Option<usize>,
	fail_read: Option<u64>,
}

impl<'a> View<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self {
			bytes,
			length: u64::try_from(bytes.len()).expect("fixture length fits"),
			reads: RefCell::new(Vec::new()),
			checks: Cell::new(0),
			fail_check: None,
			fail_read: None,
		}
	}
}

impl ReadView for View<'_> {
	type Error = io::Error;

	fn length(&self) -> u64 {
		self.length
	}

	fn recheck_observation(&self) -> io::Result<()> {
		self.checks.set(self.checks.get() + 1);
		if self.fail_check == Some(self.checks.get()) {
			return Err(io::Error::other("fixture changed"));
		}
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
		self.reads.borrow_mut().push((offset, buffer.len()));
		if self.fail_read == Some(offset) {
			buffer[0] = 0;
			return Err(ErrorKind::UnexpectedEof.into());
		}
		let start = usize::try_from(offset).expect("fixture offset fits");
		buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
		Ok(())
	}
}

#[test]
fn equal_inputs_read_every_byte_with_exact_tail_width() {
	let left = View::new(b"abc\x00\x00\xffz");
	let right = View::new(left.bytes);
	let result = compare(&left, &right, &mut [0; 5]).expect("comparison completes");

	assert_eq!(result, LiveComparison::Equal { length: 7 });
	for view in [&left, &right] {
		assert_eq!(*view.reads.borrow(), [(0, 2), (2, 2), (4, 2), (6, 1)]);
		assert_eq!(view.checks.get(), 2);
	}
}

#[test]
fn independently_checks_each_mismatch_position_with_multiple_window_widths() {
	let original = b"\x00a\x00b\x00c\x00";
	for scratch_len in 2..=original.len() * 2 + 1 {
		for index in 0..original.len() {
			let mut modified = *original;
			modified[index] = modified[index].wrapping_add(1);
			let left = View::new(original);
			let right = View::new(&modified);
			let offset = u64::try_from(index).expect("fixture offset fits");
			let window = scratch_len / 2;

			assert_eq!(
				compare(&left, &right, &mut vec![0; scratch_len]).expect("difference"),
				LiveComparison::Different(Difference::FirstByte { offset })
			);
			for view in [&left, &right] {
				assert_eq!(view.reads.borrow().len(), index / window + 1);
				assert_eq!(view.checks.get(), 2);
			}
		}
	}
}

#[test]
fn reports_different_lengths_and_empty_equality_without_data_reads() {
	for (left_len, right_len, expected) in [
		(0, 0, LiveComparison::Equal { length: 0 }),
		(
			0,
			MAX_FILE_LENGTH,
			LiveComparison::Different(Difference::Length {
				left: 0,
				right: MAX_FILE_LENGTH,
			}),
		),
		(
			MAX_FILE_LENGTH,
			0,
			LiveComparison::Different(Difference::Length {
				left: MAX_FILE_LENGTH,
				right: 0,
			}),
		),
	] {
		let left = View {
			length: left_len,
			..View::new(b"")
		};
		let right = View {
			length: right_len,
			..View::new(b"")
		};
		assert_eq!(compare(&left, &right, &mut []).unwrap(), expected);
		for view in [&left, &right] {
			assert!(view.reads.borrow().is_empty());
			assert_eq!(view.checks.get(), 2);
		}
	}
}

#[test]
fn refuses_out_of_bounds_input_before_observing_or_reading_either_file() {
	let ordinary = View::new(b"a");
	let too_large = View {
		length: MAX_FILE_LENGTH + 1,
		..View::new(b"")
	};
	for (left, right, expected_side) in [
		(&too_large, &ordinary, Side::Left),
		(&ordinary, &too_large, Side::Right),
	] {
		assert!(matches!(
			compare(left, right, &mut [0; 2]),
			Err(CompareError::FileTooLong { side, length })
				if side == expected_side && length == too_large.length
		));
	}

	let mut maximum_scratch = vec![0; MAX_SCRATCH_BYTES + 1];
	assert!(matches!(
		compare(&ordinary, &ordinary, &mut maximum_scratch),
		Err(CompareError::ScratchTooLarge { length }) if length == maximum_scratch.len()
	));
	for size in [0, 1] {
		assert!(matches!(
			compare(&ordinary, &ordinary, &mut [0][..size]),
			Err(CompareError::InsufficientScratch)
		));
	}
	for view in [&ordinary, &too_large] {
		assert_eq!(view.checks.get(), 0);
		assert!(view.reads.borrow().is_empty());
	}

	assert_eq!(
		compare(
			&ordinary,
			&ordinary,
			&mut maximum_scratch[..MAX_SCRATCH_BYTES],
		)
		.unwrap(),
		LiveComparison::Equal { length: 1 }
	);
}

#[test]
fn read_failure_overrides_equality_and_reports_side_and_requested_offset() {
	for failing_side in [Side::Left, Side::Right] {
		let ordinary = View::new(b"aaaa");
		let broken = View {
			fail_read: Some(2),
			..View::new(b"aaaa")
		};
		let (left, right) = match failing_side {
			Side::Left => (&broken, &ordinary),
			Side::Right => (&ordinary, &broken),
		};
		let error = compare(left, right, &mut [0; 4]).unwrap_err();
		let detail = std::error::Error::source(&error)
			.and_then(|source| source.downcast_ref::<io::Error>())
			.unwrap();
		assert_eq!(detail.kind(), ErrorKind::UnexpectedEof);
		assert!(matches!(
			error,
			CompareError::Read {
				side,
				offset: 2,
				..
			} if side == failing_side
		));
		assert_eq!(*broken.reads.borrow(), [(0, 2), (2, 2)]);
		assert_eq!(left.checks.get(), 1);
		assert_eq!(right.checks.get(), 1);
	}
}

#[test]
fn observation_failure_makes_every_kind_of_decision_inconclusive() {
	for (left_bytes, right_bytes) in [
		(&b""[..], &b""[..]),
		(b"", b"x"),
		(b"x", b"y"),
		(b"x", b"x"),
	] {
		for boundary in 1..=2 {
			for failing_side in [Side::Left, Side::Right] {
				let left = View {
					fail_check: (failing_side == Side::Left).then_some(boundary),
					..View::new(left_bytes)
				};
				let right = View {
					fail_check: (failing_side == Side::Right).then_some(boundary),
					..View::new(right_bytes)
				};
				let error = compare(&left, &right, &mut [0; 2]).unwrap_err();
				assert!(matches!(
					error,
					CompareError::Observation { side, .. } if side == failing_side
				));
				if boundary == 1 {
					assert!(left.reads.borrow().is_empty());
					assert!(right.reads.borrow().is_empty());
				}
			}
		}
	}
}
