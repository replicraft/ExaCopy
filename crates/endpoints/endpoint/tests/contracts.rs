//! Boundary and fault cases for the shared adapter contracts.

use std::error::Error as _;
use std::io;

use exacopy_endpoint::{
	IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES, MAX_UNIX_COMPONENT_BYTES, NameError,
	UnixComponent, read_exact_at, write_all_at,
};

#[test]
fn components_preserve_raw_bytes_and_redact_debug_output() {
	let raw = b"file\\name-\xff";
	let component = UnixComponent::new(raw).unwrap();
	assert_eq!(component.as_bytes(), raw);
	assert_eq!(format!("{component:?}"), "UnixComponent(<redacted>)");
	assert!(UnixComponent::new(&[b'x'; MAX_UNIX_COMPONENT_BYTES]).is_ok());
}

#[test]
fn components_reject_traversal_and_path_like_inputs() {
	let too_long = [b'x'; MAX_UNIX_COMPONENT_BYTES + 1];
	let invalid = [
		(&b""[..], NameError::Empty),
		(&too_long[..], NameError::TooLong),
		(&b"."[..], NameError::Reserved),
		(&b".."[..], NameError::Reserved),
		(&b"/absolute"[..], NameError::Separator),
		(&b"nested/name"[..], NameError::Separator),
		(&b"truncated\0name"[..], NameError::Nul),
	];
	for (bytes, expected) in invalid {
		let error = UnixComponent::new(bytes).unwrap_err();
		assert_eq!(error, expected);
		assert!(!error.to_string().is_empty());
	}
}

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
