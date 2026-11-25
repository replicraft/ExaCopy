use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use rustix::fs::{Timespec, Timestamps};

use super::super::super::{ManagedReadGrant, with_materialization_disabled};
use super::super::tests::{Fixture, make_stage, name, open_staging};
use super::StageError;

#[test]
#[ignore = "requires a local APFS fixture where strict inventory can establish zero visible xattrs"]
fn strict_native_stage_preserves_original_source_times_after_readback() {
	const SOURCE: &str = "metadata-source";
	const BODY: &[u8; 8] = b"required";
	let fixture = Fixture::new();
	let source_path = fixture.path(SOURCE);
	let mut initial = File::options()
		.create_new(true)
		.mode(0o600)
		.write(true)
		.open(&source_path)
		.unwrap();
	initial.write_all(BODY).unwrap();
	let original_times = Timestamps {
		last_access: Timespec {
			tv_sec: 1_610_000_000,
			tv_nsec: 123_456_789,
		},
		last_modification: Timespec {
			tv_sec: 1_620_000_000,
			tv_nsec: 987_654_321,
		},
	};
	rustix::fs::futimens(&initial, &original_times).unwrap();
	drop(initial);

	let root = fixture.bind();
	let source = root
		.open_regular_source(
			source_path.parent().unwrap(),
			name(SOURCE.as_bytes()),
			ManagedReadGrant::trusted_owner_authorizes_provisioned_root(),
		)
		.unwrap();
	let metadata = source
		.check_basic_metadata()
		.expect("admit a native source under the strict no-xattr profile");
	assert_eq!(
		metadata.atime().seconds(),
		original_times.last_access.tv_sec
	);
	assert_eq!(metadata.atime().nanoseconds(), 123_456_789);
	assert_eq!(metadata.mtime().nanoseconds(), 987_654_321);
	let staging = open_staging(&root);
	let mut writer = make_stage(&staging, source.length()).unwrap();
	let identity = writer.identity();
	let mut bytes = [0; BODY.len()];
	source.read_exact_at(0, &mut bytes).unwrap();
	source.revalidate().unwrap();
	writer.write_next(&bytes).unwrap();
	let stage = writer.flush_and_close().unwrap();

	{
		let reader = stage.open_read_back().unwrap();
		reader.read_exact_at(0, &mut bytes).unwrap();
		reader.revalidate().unwrap();
		assert_eq!(&bytes, BODY);
	}
	let ready = stage.apply_basic_metadata(&source).unwrap();
	assert_eq!(ready.identity(), identity);
	assert_eq!(ready.metadata(), metadata);
	with_materialization_disabled(|| {
		let stat = ready.check_published_descriptor()?;
		assert!(ready.matches_published_stat(&stat));
		Ok::<(), StageError>(())
	})
	.unwrap();

	let actual = fs::symlink_metadata(fixture.stage_path()).unwrap();
	assert_eq!(actual.atime(), original_times.last_access.tv_sec);
	assert_eq!(actual.atime_nsec(), original_times.last_access.tv_nsec);
	assert_eq!(actual.mtime(), original_times.last_modification.tv_sec);
	assert_eq!(
		actual.mtime_nsec(),
		original_times.last_modification.tv_nsec
	);
	assert!(!fixture.path("target").exists());
}
