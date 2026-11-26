use std::error::Error as _;
use std::fs::{self, File};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use exacopy_endpoint::{ClosedStage, FreshStage, MetadataSource, ReadView, RequiredMetadataStage};
use rustix::fs::{Timespec, Timestamps, XattrFlags};

use super::super::super::{
	BasicMetadataError, ManagedReadError, ManagedReadGrant, with_materialization_disabled,
};
use super::super::tests::{Fixture, make_stage, name, open_staging};
use super::StageError;

#[test]
fn visible_source_attribute_refuses_metadata_application_and_preserves_private_stage() {
	const SOURCE: &str = "attributed-source";
	const ATTRIBUTE: &str = "org.replicraft.exacopy.strict-metadata-fixture";
	const BODY: &[u8] = b"\0required\xFF";
	let fixture = Fixture::new();
	let source_path = fixture.path(SOURCE);
	let mut initial = File::options()
		.create_new(true)
		.mode(0o600)
		.write(true)
		.open(&source_path)
		.expect("create owner-private source fixture");
	initial.write_all(BODY).unwrap();
	rustix::fs::fsetxattr(&initial, ATTRIBUTE, b"", XattrFlags::CREATE)
		.expect("attach a visible empty xattr to the source fixture");
	drop(initial);

	let root = fixture.bind();
	let selected = crate::macos::ManagedSourceName::new(name(SOURCE.as_bytes())).unwrap();
	let source = root
		.open_regular_source(
			source_path.parent().unwrap(),
			&selected,
			ManagedReadGrant::trusted_owner_authorizes_provisioned_root(),
		)
		.expect("obtain the read-only source before strict metadata admission");
	let metadata_error = MetadataSource::admit_metadata(&source)
		.expect_err("metadata preflight rejects a visible source xattr");
	assert!(matches!(
		metadata_error,
		ManagedReadError::BasicMetadata(BasicMetadataError::ExtendedAttributes)
	));

	let staging = open_staging(&root);
	let mut writer = make_stage(&staging, source.length()).unwrap();
	assert_eq!(
		FreshStage::unwritten_length(&writer).unwrap(),
		source.length()
	);
	let mut bytes = [0; BODY.len()];
	source.read_exact_at(0, &mut bytes).unwrap();
	source.revalidate().unwrap();
	FreshStage::write_next(&mut writer, &bytes).unwrap();
	assert!(matches!(
		FreshStage::unwritten_length(&writer),
		Err(StageError::AlreadyWritten)
	));
	let stage = FreshStage::sync_and_close(writer).unwrap();
	{
		let reader = ClosedStage::open_read_back(&stage).unwrap();
		assert_eq!(ReadView::length(&reader), source.length());
		let mut readback = [0; BODY.len()];
		ReadView::read_exact_at(&reader, 0, &mut readback).unwrap();
		ReadView::recheck_observation(&reader).unwrap();
		assert_eq!(
			&readback, BODY,
			"verify stage bytes before metadata application"
		);
	}

	let stage_path = fixture.stage_path();
	let before = fs::symlink_metadata(&stage_path).unwrap();
	let error = RequiredMetadataStage::apply_metadata(stage, &source)
		.expect_err("strict metadata application must refuse a visible source xattr");
	let source_error = error
		.source()
		.and_then(|cause| cause.downcast_ref::<ManagedReadError>())
		.expect("the stage error exposes its typed source admission failure");
	assert!(matches!(
		source_error
			.source()
			.and_then(|cause| cause.downcast_ref::<BasicMetadataError>()),
		Some(BasicMetadataError::ExtendedAttributes)
	));
	assert!(error.to_string().contains("metadata"));
	assert!(
		matches!(
			error,
			StageError::Managed(ManagedReadError::BasicMetadata(
				BasicMetadataError::ExtendedAttributes
			))
		),
		"metadata refusal must retain source error provenance: {error:?}"
	);
	let after = fs::symlink_metadata(&stage_path).unwrap();
	assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
	assert_eq!(
		(after.ctime(), after.ctime_nsec()),
		(before.ctime(), before.ctime_nsec())
	);
	assert_eq!(after.accessed().unwrap(), before.accessed().unwrap());
	assert_eq!(after.modified().unwrap(), before.modified().unwrap());
	source
		.revalidate()
		.expect("retain the original source observation");
	assert_eq!(
		rustix::fs::getxattr_query(&source_path, ATTRIBUTE).unwrap(),
		0
	);
	assert_eq!(fs::read(source_path).unwrap(), BODY);
	assert_eq!(fs::read(stage_path).unwrap(), BODY);
	assert_eq!(
		fs::symlink_metadata(fixture.path("target"))
			.unwrap_err()
			.kind(),
		io::ErrorKind::NotFound
	);
}

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
	let selected = crate::macos::ManagedSourceName::new(name(SOURCE.as_bytes())).unwrap();
	let source = root
		.open_regular_source(
			source_path.parent().unwrap(),
			&selected,
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
		let held = ready.check_published_metadata()?;
		assert_eq!(held.length, source.length());
		assert_eq!(held.times.access.seconds(), metadata.atime().seconds());
		assert_eq!(
			held.times.modification.seconds(),
			metadata.mtime().seconds()
		);
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
