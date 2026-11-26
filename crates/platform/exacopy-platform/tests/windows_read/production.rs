use std::fs::{self, FileTimes, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::time::{Duration, UNIX_EPOCH};

use exacopy_diff::{CompareError, LiveComparison, Side, compare};
use exacopy_endpoint::ReadView as _;
use exacopy_platform::windows::WindowsReadFile;
use windows_sys::Win32::Storage::FileSystem::{
	FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
};

use super::cases::Fixture;

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn production_reader_refuses_changed_live_observation() {
	let fixture = Fixture::new();
	let source = fixture.0.join("source");
	let reference = fixture.0.join("reference");
	let payload = b"fixed comparison bytes";
	for path in [&source, &reference] {
		fs::write(path, payload).expect("create synthetic comparison inputs");
	}
	// Attribute-only rights do not request data writes or replacement rights.
	// Keep this synthetic fault-injection handle while binding the real reader.
	let metadata_only = OpenOptions::new()
		.access_mode(FILE_WRITE_ATTRIBUTES)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.open(&source)
		.expect("open only attribute rights on the synthetic source");
	let initial = fs::metadata(&source).unwrap().modified().unwrap();
	let left = WindowsReadFile::open_absolute(&source).expect("bind the production source view");
	let right = WindowsReadFile::open_absolute(&reference).expect("bind the production reference");
	let mut scratch = [0; 8];
	assert_eq!(
		compare(&left, &right, &mut scratch).expect("equal before the controlled change"),
		LiveComparison::Equal {
			length: left.length()
		}
	);

	const OBSERVED_EARLIER_TIME: Duration = Duration::from_secs(1_600_000_000);
	let changed_time = UNIX_EPOCH + OBSERVED_EARLIER_TIME;
	assert_ne!(initial, changed_time);
	metadata_only
		.set_times(FileTimes::new().set_modified(changed_time))
		.expect("change only the synthetic source modification time");
	drop(metadata_only);
	assert_eq!(
		fs::metadata(&source).unwrap().modified().unwrap(),
		changed_time
	);
	let refusal = compare(&left, &right, &mut scratch).unwrap_err();
	assert!(
		matches!(&refusal, CompareError::Observation { side: Side::Left, source }
			if source.to_string() == "held comparison input changed"),
		"{refusal:?}"
	);
	drop((left, right));
	for path in [source, reference] {
		assert_eq!(fs::read(path).expect("read preserved input bytes"), payload);
	}
}
