use std::fs;
use std::num::NonZeroUsize;
use std::os::windows::io::AsHandle;

use exacopy_diff::{Difference, LiveComparison, compare, compare_parallel};
use exacopy_endpoint::ReadView;
use exacopy_platform::windows::WindowsComponent;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

use super::{CompareInputError, HeldDirectory};
use crate::cases::{Fixture, directory_handle};

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_exact_comparison_uses_the_held_ntfs_views() {
	let fixture = Fixture::new();
	let payload = b"first\0line\xff\r\nlast";
	for name in ["left", "equal"] {
		fs::write(fixture.0.join(name), payload).expect("create equal independent inputs");
	}
	let mut different = *payload;
	different[10] = 0;
	fs::write(fixture.0.join("different"), different).expect("create equal-length difference");
	fs::write(fixture.0.join("shorter"), &payload[..8]).expect("create length difference");
	let directory = directory_handle(&fixture.0, FILE_SHARE_READ);
	let mut held = HeldDirectory::inspect(directory.as_handle()).expect("admit fixed NTFS parent");
	let mut open = |name: &str| {
		let units: Vec<_> = name.encode_utf16().collect();
		held.open_comparison(WindowsComponent::new(&units).expect("admit fixture name"))
			.expect("open by ID with overlapped read-only rights")
	};
	let left = open("left");
	let equal = open("equal");
	let distinct = open("different");
	let shorter = open("shorter");
	let expected_length = u64::try_from(payload.len()).expect("bounded fixture length");
	assert!(matches!(
		left.read_exact_at(expected_length, &mut [0]),
		Err(CompareInputError::InvalidRange)
	));
	let mut bytes = [0; 5];
	left.read_exact_at(6, &mut bytes).expect("positioned read");
	assert_eq!(&bytes, &payload[6..11]);
	left.read_exact_at(0, &mut bytes)
		.expect("out-of-order read");
	assert_eq!(&bytes, &payload[..5]);

	let workers = NonZeroUsize::new(2).expect("two workers");
	for (right, expected) in [
		(
			&equal,
			LiveComparison::Equal {
				length: expected_length,
			},
		),
		(
			&distinct,
			LiveComparison::Different(Difference::FirstByte { offset: 10 }),
		),
		(
			&shorter,
			LiveComparison::Different(Difference::Length {
				left: expected_length,
				right: 8,
			}),
		),
	] {
		let mut scratch = [0; 8];
		assert_eq!(
			compare(&left, right, &mut scratch).expect("serial exact comparison"),
			expected
		);
		assert_eq!(
			compare_parallel(&left, right, &mut scratch, workers)
				.expect("parallel exact comparison"),
			expected
		);
	}

	drop((left, equal, distinct, shorter));
	for (name, expected) in [
		("left", &payload[..]),
		("equal", &payload[..]),
		("different", &different[..]),
		("shorter", &payload[..8]),
	] {
		assert_eq!(
			fs::read(fixture.0.join(name)).expect("independent post-run byte oracle"),
			expected
		);
	}
}
