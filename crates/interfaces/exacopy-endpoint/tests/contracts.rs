//! Boundary and fault cases for the shared adapter contracts.

use std::error::Error as _;
use std::io;

use exacopy_endpoint::{
	IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES, read_exact_at, write_all_at,
};

#[test]
fn advances_short_reads_and_retries_the_same_position_on_interruption() {
	let mut output = [0; 5];
	let mut calls = Vec::new();
	let input = b"abcde";
	let start = 100;
	read_exact_at(start, &mut output, |position, remaining| {
		calls.push((position, remaining.len()));
		if calls.len() == 2 {
			return Err(io::ErrorKind::Interrupted.into());
		}
		let relative = usize::try_from(position - start).unwrap();
		let count = remaining.len().min(2);
		remaining[..count].copy_from_slice(&input[relative..relative + count]);
		Ok(count)
	})
	.unwrap();
	assert_eq!(&output, input);
	assert_eq!(calls, [(100, 5), (102, 3), (102, 3), (104, 1)]);
}

#[test]
fn advances_short_writes_without_replaying_written_prefixes() {
	let mut target = *b"........";
	let mut calls = Vec::new();
	write_all_at(2, b"abcde", |position, bytes| {
		calls.push((position, bytes.to_vec()));
		if calls.len() == 2 {
			return Err(io::ErrorKind::Interrupted.into());
		}
		let index = usize::try_from(position).unwrap();
		let count = bytes.len().min(2);
		target[index..index + count].copy_from_slice(&bytes[..count]);
		Ok(count)
	})
	.unwrap();
	assert_eq!(&target, b"..abcde.");
	assert_eq!(
		calls,
		[
			(2, b"abcde".to_vec()),
			(4, b"cde".to_vec()),
			(4, b"cde".to_vec()),
			(6, b"e".to_vec())
		]
	);
}

#[test]
fn reports_early_eof_and_write_zero_at_the_first_incomplete_offset() {
	let mut output = [0; 4];
	let error = read_exact_at(9, &mut output, |position, buffer| {
		if position == 9 {
			buffer[..2].copy_from_slice(b"ab");
			Ok(2)
		} else {
			Ok(0)
		}
	})
	.unwrap_err();
	assert!(matches!(error, IoError::UnexpectedEof { offset: 11 }));
	assert_eq!(output, [b'a', b'b', 0, 0]);

	let error = write_all_at(7, b"abc", |position, _| Ok(usize::from(position == 7))).unwrap_err();
	assert!(matches!(error, IoError::WriteZero { offset: 8 }));
}

#[test]
fn rejects_impossible_results_and_retains_the_underlying_error() {
	let error = read_exact_at(7, &mut [0; 2], |_, remaining| Ok(remaining.len() + 1)).unwrap_err();
	assert!(matches!(
		error,
		IoError::InvalidTransferCount {
			offset: 7,
			count: 3,
			remaining: 2
		}
	));
	assert_eq!(
		error.to_string(),
		"positioned operation at 7 reported 3 bytes with 2 remaining"
	);

	let error = write_all_at(5, b"abc", |position, _| {
		if position == 5 {
			Ok(1)
		} else {
			Err(io::ErrorKind::StorageFull.into())
		}
	})
	.unwrap_err();
	assert!(
		matches!(&error, IoError::System { offset: 6, source } if source.kind() == io::ErrorKind::StorageFull)
	);
	assert!(error.source().is_some());
}

#[test]
fn checks_whole_extent_before_calling_the_backend_and_treats_empty_range_as_no_op() {
	let error = write_all_at(MAX_FILE_LENGTH, b"x", |_, _| {
		panic!("range exceeds the ceiling")
	})
	.unwrap_err();
	assert!(matches!(
		error,
		IoError::InvalidRange {
			offset: MAX_FILE_LENGTH,
			length: 1
		}
	));
	read_exact_at(MAX_FILE_LENGTH, &mut [], |_, _| panic!("empty read")).unwrap();
	write_all_at(MAX_FILE_LENGTH, b"", |_, _| panic!("empty write")).unwrap();
	assert!(matches!(
		read_exact_at(u64::MAX, &mut [], |_, _| panic!("invalid offset")),
		Err(IoError::InvalidRange {
			offset: u64::MAX,
			length: 0
		})
	));
	write_all_at(MAX_FILE_LENGTH - 1, b"x", |position, bytes| {
		assert_eq!(position, MAX_FILE_LENGTH - 1);
		Ok(bytes.len())
	})
	.unwrap();
}

#[test]
fn interrupted_retry_budget_resets_after_progress_and_refuses_a_signal_storm() {
	let mut attempts_at_position = [0; 2];
	let start = 50;
	write_all_at(start, b"ab", |position, _| {
		let index = usize::try_from(position - start).unwrap();
		attempts_at_position[index] += 1;
		if attempts_at_position[index] <= MAX_INTERRUPTED_RETRIES {
			Err(io::ErrorKind::Interrupted.into())
		} else {
			Ok(1)
		}
	})
	.unwrap();
	assert_eq!(attempts_at_position, [MAX_INTERRUPTED_RETRIES + 1; 2]);

	let mut interrupted = 0;
	let failure = read_exact_at(12, &mut [0], |position, _| {
		assert_eq!(position, 12);
		interrupted += 1;
		Err(io::ErrorKind::Interrupted.into())
	})
	.unwrap_err();
	assert!(
		matches!(failure, IoError::System { offset: 12, source } if source.kind() == io::ErrorKind::Interrupted)
	);
	assert_eq!(interrupted, MAX_INTERRUPTED_RETRIES + 1);
}

const HISTORY_BYTES: &[u8; 4] = b"abcd";
const HISTORY_START: u64 = MAX_FILE_LENGTH - 4;
const UNTOUCHED: u8 = b'.';

#[derive(Clone, Copy, Debug)]
enum Terminal {
	Complete,
	NoProgress,
	Overreported(usize),
	SystemError,
	Interrupted,
}

#[test]
fn checks_bounded_positioned_histories_against_scripted_suffixes() {
	for prefix in 0..=HISTORY_BYTES.len() {
		// Each mask selects the internal boundaries of one partition of the confirmed prefix.
		for cuts in 0..(1 << prefix.saturating_sub(1)) {
			let mut steps = Vec::new();
			let mut start = 0;
			for end in 1..=prefix {
				if end == prefix || cuts & (1 << (end - 1)) != 0 {
					steps.push((start, Err(io::ErrorKind::Interrupted)));
					steps.push((start, Ok(end - start)));
					start = end;
				}
			}

			if prefix == HISTORY_BYTES.len() {
				check_positioned_history(&steps, prefix, Terminal::Complete);
				continue;
			}

			let excess = HISTORY_BYTES.len() - prefix + 1;
			for (terminal, response, attempts) in [
				(Terminal::NoProgress, Ok(0), 1),
				(Terminal::Overreported(excess), Ok(excess), 1),
				(Terminal::Overreported(usize::MAX), Ok(usize::MAX), 1),
				(Terminal::SystemError, Err(io::ErrorKind::StorageFull), 1),
				(
					Terminal::Interrupted,
					Err(io::ErrorKind::Interrupted),
					MAX_INTERRUPTED_RETRIES + 1,
				),
			] {
				steps.extend(std::iter::repeat_n(
					(prefix, response),
					usize::from(attempts),
				));
				check_positioned_history(&steps, prefix, terminal);
				steps.truncate(steps.len() - usize::from(attempts));
			}
		}
	}
}

fn check_positioned_history(
	steps: &[(usize, Result<usize, io::ErrorKind>)],
	prefix: usize,
	terminal: Terminal,
) {
	let context = (steps, terminal);
	let mut read_steps = steps.iter().copied();
	let mut output = [UNTOUCHED; HISTORY_BYTES.len()];
	let read_result = read_exact_at(HISTORY_START, &mut output, |position, buffer| {
		let (start, response) = read_steps.next().expect("unscripted read callback");
		assert_eq!(
			position,
			HISTORY_START + u64::try_from(start).unwrap(),
			"{context:?}"
		);
		let expected = &HISTORY_BYTES[start..];
		assert_eq!(buffer.len(), expected.len(), "{context:?}");
		assert!(buffer.iter().all(|&byte| byte == UNTOUCHED), "{context:?}");
		if let Ok(count) = response
			&& let Some(bytes) = expected.get(..count)
		{
			buffer[..count].copy_from_slice(bytes);
		}
		response.map_err(io::Error::from)
	});
	assert_eq!(read_steps.len(), 0, "{context:?}");

	let mut write_steps = steps.iter().copied();
	let mut written = [UNTOUCHED; HISTORY_BYTES.len()];
	let write_result = write_all_at(HISTORY_START, HISTORY_BYTES, |position, buffer| {
		let (start, response) = write_steps.next().expect("unscripted write callback");
		assert_eq!(
			position,
			HISTORY_START + u64::try_from(start).unwrap(),
			"{context:?}"
		);
		assert_eq!(buffer, &HISTORY_BYTES[start..], "{context:?}");
		if let Ok(count) = response
			&& let Some(bytes) = buffer.get(..count)
		{
			written[start..start + count].copy_from_slice(bytes);
		}
		response.map_err(io::Error::from)
	});
	assert_eq!(write_steps.len(), 0, "{context:?}");

	let mut expected = [UNTOUCHED; HISTORY_BYTES.len()];
	expected[..prefix].copy_from_slice(&HISTORY_BYTES[..prefix]);
	assert_eq!(output, expected, "{context:?}");
	assert_eq!(written, expected, "{context:?}");

	let offset = HISTORY_START + u64::try_from(prefix).unwrap();
	match terminal {
		Terminal::Complete => {
			read_result.unwrap();
			write_result.unwrap();
		}
		Terminal::NoProgress => {
			assert!(
				matches!(read_result, Err(IoError::UnexpectedEof { offset: actual }) if actual == offset),
				"{context:?}"
			);
			assert!(
				matches!(write_result, Err(IoError::WriteZero { offset: actual }) if actual == offset),
				"{context:?}"
			);
		}
		Terminal::Overreported(reported) => {
			for result in [read_result, write_result] {
				assert!(
					matches!(
						result,
						Err(IoError::InvalidTransferCount {
							offset: actual,
							count,
							remaining,
						}) if actual == offset && count == reported && remaining == HISTORY_BYTES.len() - prefix
					),
					"{context:?}"
				);
			}
		}
		Terminal::SystemError | Terminal::Interrupted => {
			let expected = match terminal {
				Terminal::Interrupted => io::ErrorKind::Interrupted,
				_ => io::ErrorKind::StorageFull,
			};
			for result in [read_result, write_result] {
				assert!(
					matches!(
						result,
						Err(IoError::System { offset: actual, source })
							if actual == offset && source.kind() == expected
					),
					"{context:?}"
				);
			}
		}
	}
}

#[test]
fn compares_positioned_range_admission_with_a_wider_sum() {
	let ceiling = i64::MAX.cast_unsigned();
	for offset in [0, ceiling - 2, ceiling - 1, ceiling, ceiling + 1, u64::MAX] {
		for length in 0..=HISTORY_BYTES.len() {
			let admitted =
				u128::from(offset) + u128::try_from(length).unwrap() <= u128::from(ceiling);
			let mut output = [UNTOUCHED; HISTORY_BYTES.len()];
			let mut read_calls = 0;
			let mut write_calls = 0;
			let read_result = read_exact_at(offset, &mut output[..length], |position, buffer| {
				assert_eq!((position, buffer.len()), (offset, length));
				read_calls += 1;
				buffer.copy_from_slice(&HISTORY_BYTES[..length]);
				Ok(buffer.len())
			});
			let write_result =
				write_all_at(offset, &HISTORY_BYTES[..length], |position, buffer| {
					assert_eq!((position, buffer.len()), (offset, length));
					write_calls += 1;
					Ok(buffer.len())
				});

			let calls = usize::from(admitted && length != 0);
			assert_eq!(
				(read_calls, write_calls),
				(calls, calls),
				"{offset}, {length}"
			);
			for result in [read_result, write_result] {
				if admitted {
					result.unwrap();
				} else {
					assert!(
						matches!(
							result,
							Err(IoError::InvalidRange {
								offset: actual_offset,
								length: actual_length,
							}) if (actual_offset, actual_length) == (offset, length)
						),
						"{offset}, {length}"
					);
				}
			}
		}
	}
}
