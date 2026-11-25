//! Positioned I/O error diagnostics and published limits.

use std::error::Error as _;
use std::io;

use exacopy_endpoint::{
	IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES, MAX_UNIX_COMPONENT_BYTES, read_exact_at,
	write_all_at,
};

#[test]
fn baseline_limits_match_the_endpoint_contract() {
	assert_eq!(MAX_FILE_LENGTH, 9_223_372_036_854_775_807);
	assert_eq!(MAX_INTERRUPTED_RETRIES, 16);
	assert_eq!(MAX_UNIX_COMPONENT_BYTES, 255);
}

#[test]
fn invalid_range_names_the_rejected_offset_and_length() {
	const START: u64 = u64::MAX;
	let error = write_all_at(START, b"xy", |_, _| {
		panic!("invalid range reached the writer")
	})
	.expect_err("write exceeds the file extent limit");
	assert!(matches!(
		error,
		IoError::InvalidRange {
			offset: START,
			length: 2
		}
	));
	assert_eq!(
		error.to_string(),
		format!("2 bytes at offset {START} exceed the file extent limit")
	);
	assert!(error.source().is_none());
}

#[test]
fn early_eof_names_the_first_unread_offset() {
	const START: u64 = 29;
	let mut output = [0; 4];
	let error = read_exact_at(START, &mut output, |position, buffer| {
		if position == START {
			buffer[..2].copy_from_slice(b"ok");
			Ok(2)
		} else {
			Ok(0)
		}
	})
	.expect_err("reader stopped with bytes remaining");
	assert!(matches!(error, IoError::UnexpectedEof { offset: 31 }));
	assert_eq!(error.to_string(), "unexpected end of file at offset 31");
	assert!(error.source().is_none());
}

#[test]
fn zero_write_names_the_first_unwritten_offset() {
	const START: u64 = 73;
	let error = write_all_at(START, b"data", |position, _| {
		Ok(if position == START { 2 } else { 0 })
	})
	.expect_err("writer stopped with bytes remaining");
	assert!(matches!(error, IoError::WriteZero { offset: 75 }));
	assert_eq!(error.to_string(), "write made no progress at offset 75");
	assert!(error.source().is_none());
}

#[test]
fn impossible_transfer_names_the_offset_and_both_counts() {
	let mut reported_counts = [2, 4].into_iter();
	let error = write_all_at(100, b"hello", |_, _| {
		Ok(reported_counts
			.next()
			.expect("writer stops at the first impossible count"))
	})
	.expect_err("writer reported more bytes than the supplied suffix");
	assert!(matches!(
		error,
		IoError::InvalidTransferCount {
			offset: 102,
			count: 4,
			remaining: 3
		}
	));
	assert_eq!(
		error.to_string(),
		"positioned operation at 102 reported 4 bytes with 3 remaining"
	);
	assert!(error.source().is_none());
}

#[test]
fn system_failure_names_the_offset_and_preserves_the_raw_os_cause() {
	const START: u64 = 64;
	const RAW_OS_FAILURE: i32 = 28;
	let error = write_all_at(START, b"data", |position, _| {
		if position == START {
			Ok(2)
		} else {
			Err(io::Error::from_raw_os_error(RAW_OS_FAILURE))
		}
	})
	.expect_err("backend returned an OS error after writing a prefix");
	assert!(
		matches!(&error, IoError::System { offset: 66, source } if source.raw_os_error() == Some(RAW_OS_FAILURE))
	);
	let cause = error
		.source()
		.and_then(|source| source.downcast_ref::<io::Error>())
		.expect("OS errors remain available through the structured error chain");
	assert_eq!(cause.raw_os_error(), Some(RAW_OS_FAILURE));
	assert_eq!(
		error.to_string(),
		format!("positioned operation at 66 failed with {cause}")
	);
}
