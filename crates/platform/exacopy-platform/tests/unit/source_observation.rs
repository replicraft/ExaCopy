use std::fs;

use exacopy_endpoint::UnixComponent;
use rustix::fs::fstat;

use super::{ReadError, SourceObservation, SourceTimestamp};
use crate::linux::ReadRoot;
use crate::scratch::Scratch;

#[test]
fn capture_refuses_a_directory_descriptor() {
	let scratch = Scratch::new();
	let directory = scratch.open();
	let stat = fstat(&directory).expect("observe the real fixture directory");
	assert!(
		matches!(
			SourceObservation::capture(&stat),
			Err(ReadError::NotRegularFile)
		),
		"a directory observation cannot represent a regular source"
	);
}

#[test]
fn recheck_recognizes_a_hard_link_but_rejects_an_independent_equal_file() {
	const CONTENTS: &[u8] = b"same bytes";

	let scratch = Scratch::new();
	fs::write(scratch.path("original"), CONTENTS).expect("write the original fixture");
	fs::hard_link(scratch.path("original"), scratch.path("alias"))
		.expect("make another name for the original inode");
	fs::write(scratch.path("independent"), CONTENTS).expect("write an independent fixture");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit the fixture root");
	let original = root
		.open_regular(UnixComponent::new(b"original").expect("valid original name"))
		.expect("hold the original inode");
	let alias = root
		.open_regular(UnixComponent::new(b"alias").expect("valid alias name"))
		.expect("hold the same inode through its alias");
	let independent = root
		.open_regular(UnixComponent::new(b"independent").expect("valid independent name"))
		.expect("hold the independent inode");

	let observed = original.observation();
	assert_eq!(observed.link_count(), 2, "the original has two names");
	assert_eq!(
		independent.observation().link_count(),
		1,
		"equal contents do not share the original inode"
	);
	observed
		.recheck(alias.observation())
		.expect("the alias carries the same inode observation");
	assert!(
		matches!(
			observed.recheck(independent.observation()),
			Err(ReadError::IdentityChanged)
		),
		"equal contents on an independent inode must report an identity change"
	);
}

#[test]
fn timestamp_capture_rejects_fractions_outside_the_valid_interval() {
	const BEFORE_EPOCH: i64 = -1;
	const NANOS_PER_SECOND: u64 = 1_000_000_000;

	let last_nanosecond = SourceTimestamp::capture(BEFORE_EPOCH, NANOS_PER_SECOND - 1)
		.expect("the final nanosecond of a negative Unix second is representable");
	assert_eq!(last_nanosecond.seconds(), BEFORE_EPOCH);
	assert_eq!(
		u64::from(last_nanosecond.nanoseconds()),
		NANOS_PER_SECOND - 1
	);
	for fraction in [NANOS_PER_SECOND, u64::from(u32::MAX) + 1] {
		assert!(
			matches!(
				SourceTimestamp::capture(BEFORE_EPOCH, fraction),
				Err(ReadError::InvalidTimestamp)
			),
			"invalid nanosecond fraction {fraction} must be refused"
		);
	}
}
