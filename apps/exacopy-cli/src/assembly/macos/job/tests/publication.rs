use std::error::Error;
use std::io;
use std::time::Duration;

use super::*;
use crate::assembly::macos::StageTransferFailure;
use crate::assembly::macos::receipt::{DarwinCopyReceipt, DarwinReceiptFrames};
use exacopy_journal::DarwinReceiptCommitted;

#[test]
fn prepared_copy_refuses_visible_source_metadata_before_any_content_or_intent() {
	let fixture = Fixture::new();
	assert!(
		Command::new("/usr/bin/xattr")
			.args(["-w", "com.example.exacopy-publication", "fixture"])
			.arg(fixture.0.join(SOURCE))
			.status()
			.unwrap()
			.success()
	);
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
	let path = fixture.0.join(PRIVATE).join(name.to_string());
	let destination = admit_destination(plan.destination(), request).unwrap();
	with_admitted_job(&plan, request, name, destination, |job| {
		job.with_admitted_entry(|entry| {
			let original = fs::read(path.join(FIRST_SEGMENT)).unwrap();
			let mut scratch = [0; 256];
			let refused = entry.copy_and_publish(&mut scratch).unwrap_err();
			assert_eq!(refused.job(), name);
			assert_eq!(refused.progress(), PublicationProgress::Private);
			assert!(matches!(
				refused.failure(),
				DarwinCopyFailure::Source(ManagedReadError::BasicMetadata(
					BasicMetadataError::ExtendedAttributes
				))
			));
			let repeat = entry.copy_and_publish(&mut scratch).unwrap_err();
			assert!(matches!(
				repeat.failure(),
				DarwinCopyFailure::AlreadyAttempted
			));
			assert_eq!(repeat.progress(), PublicationProgress::Private);
			assert_eq!(fs::read(path.join(FIRST_SEGMENT)).unwrap(), original);
			assert_eq!(fs::metadata(path.join("stage/payload")).unwrap().len(), 0);
			assert!(!fixture.0.join(TARGET).exists());
			assert!(!path.join("receipts").exists());
		})
		.unwrap();
	})
	.unwrap();
	assert_eq!(fs::read(fixture.0.join(SOURCE)).unwrap(), PAYLOAD);
}

#[test]
#[ignore = "requires a local APFS fixture that passes strict metadata admission"]
fn strict_native_copy_publishes_the_stage_and_commits_its_receipt() {
	assert_strict_copy(&Fixture::new(), None);
}

#[test]
#[ignore = "requires local APFS with strict metadata and a timestamp-eligible synthetic source"]
fn strict_native_copy_with_timestamp_eligible_source_commits_its_receipt() {
	// Construct this source with a modification time later than a fresh stage's
	// birth time. Darwin can move birth backwards when installing an earlier mtime.
	const FIXTURE_MTIME_OFFSET: Duration = Duration::from_secs(3_600);
	let modified = SystemTime::now() + FIXTURE_MTIME_OFFSET;
	let fixture = Fixture::with_source_modification_time(Some(modified));
	assert_strict_copy(&fixture, Some(modified));
}

fn assert_strict_copy(fixture: &Fixture, expected_mtime: Option<SystemTime>) {
	let root = open_root(&fixture.0).unwrap_or_else(|error| {
		if matches!(
			error,
			StageError::Managed(ManagedReadError::UnsupportedNamespace)
		) {
			eprintln!("qualification=blocked reason=unsupported-managed-apfs-root");
		}
		panic!("failed to admit fixture root: {error:?}");
	});
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
	let path = fixture.0.join(PRIVATE).join(name.to_string());
	let original_source = fs::metadata(fixture.0.join(SOURCE)).unwrap();
	let receipt = with_prepared_job(&plan, request, |job| {
		job.with_prepared_entry(|entry| {
			let identity = entry.preparation().preparation().stage.identity;
			let inode = identity.inode().get();
			let stage_path = path.join("stage/payload");
			let original_stage = fs::symlink_metadata(&stage_path).unwrap();
			assert_eq!(original_stage.ino(), inode);
			let birth = original_stage.created().unwrap();
			let modified = original_source.modified().unwrap();
			if let Some(expected) = expected_mtime {
				assert_eq!(modified, expected);
				assert!(
					modified > birth,
					"qualification=blocked reason=stage-born-after-synthetic-mtime"
				);
			}
			let mut scratch = [0; 256];
			let receipt = entry
				.copy_and_publish(&mut scratch)
				.unwrap_or_else(|error| {
					if let Some(reason) =
						copy_block_reason(&error, &stage_path, &original_stage, modified)
					{
						assert_preserved_without_publication(fixture);
						let retained = fs::symlink_metadata(&stage_path).unwrap();
						assert_eq!(
							(retained.dev(), retained.ino()),
							(original_stage.dev(), inode)
						);
						assert_absent(&path.join("receipts"));
						let mut prefix = FrameReader::new(
							File::open(path.join(FIRST_SEGMENT)).unwrap(),
							ChainHead::start(),
						);
						while let Some(frame) = prefix.next_frame().unwrap() {
							assert!(!matches!(
								frame.kind(),
								FrameKind::PublishIntent
									| FrameKind::PublishObserved
									| FrameKind::DurabilityRecorded
									| FrameKind::ReceiptCommitted
							));
						}
						eprintln!("qualification=blocked reason={reason}");
					}
					panic!("copy through receipt failed: {error:?}");
				});
			let target = fs::symlink_metadata(fixture.0.join(TARGET)).unwrap();
			assert_eq!((target.dev(), target.ino()), (original_stage.dev(), inode));
			assert_eq!(target.created().unwrap(), birth);
			assert_eq!(target.modified().unwrap(), modified);
			assert_eq!(
				target.accessed().unwrap(),
				original_source.accessed().unwrap()
			);
			assert_eq!(target.mode(), original_source.mode());
			assert_eq!(target.uid(), original_source.uid());
			assert_eq!(target.gid(), original_source.gid());
			let stream = receipt.evidence().stream;
			assert_eq!(stream.identity, identity);
			assert_eq!(stream.length.get(), u64::try_from(PAYLOAD.len()).unwrap());
			assert_eq!(stream.digest.as_bytes(), blake3::hash(PAYLOAD).as_bytes());
			assert_ne!(
				target.ino(),
				fs::metadata(fixture.0.join(SOURCE)).unwrap().ino()
			);
			assert_absent(&stage_path);
			assert_eq!(
				fs::read(path.join("receipts/receipt.cbor")).unwrap(),
				receipt.encode()
			);
			let repeat = entry.copy_and_publish(&mut scratch).unwrap_err();
			assert_eq!(repeat.progress(), PublicationProgress::ReceiptCommitted);
			assert!(matches!(
				repeat.failure(),
				DarwinCopyFailure::AlreadyAttempted
			));
			receipt.encode()
		})
		.unwrap()
	})
	.unwrap_or_else(|error| {
		if matches!(error, JobBootstrapError::Admission(_)) && has_extended_attributes(&error) {
			fixture.assert_no_job();
			assert_preserved_without_publication(fixture);
			eprintln!("qualification=blocked reason=strict-source-extended-attributes");
		}
		panic!("strict source or job preparation refused: {error:?}");
	});
	let receipt = DarwinCopyReceipt::decode(&receipt).unwrap();
	let mut reader = FrameReader::new(
		File::open(path.join(FIRST_SEGMENT)).unwrap(),
		ChainHead::start(),
	);
	let [
		_,
		_,
		_,
		verification,
		metadata,
		intent,
		observed,
		durability,
	] = [
		FrameKind::JobPrepared,
		FrameKind::EntryPrepared,
		FrameKind::StageSealed,
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
	]
	.map(|kind| {
		let frame = reader.next_frame().unwrap().unwrap();
		assert_eq!(kind, frame.kind());
		frame
	});
	receipt
		.validate_evidence(
			&plan,
			DarwinReceiptFrames {
				verification: &verification,
				metadata: &metadata,
				intent: &intent,
				observed: &observed,
				durability: &durability,
			},
		)
		.unwrap();
	let committed = reader.next_frame().unwrap().unwrap();
	assert_eq!(committed.kind(), FrameKind::ReceiptCommitted);
	DarwinReceiptCommitted::from_frame(&committed)
		.unwrap()
		.validate_evidence(&durability, receipt.digest())
		.unwrap();
	assert!(reader.next_frame().unwrap().is_none());
	assert_eq!(fs::read(fixture.0.join(TARGET)).unwrap(), PAYLOAD);
	assert_eq!(fs::read(fixture.0.join(SOURCE)).unwrap(), PAYLOAD);
	println!("qualification=pass");
}

fn assert_preserved_without_publication(fixture: &Fixture) {
	assert_absent(&fixture.0.join(TARGET));
	assert_eq!(fs::read(fixture.0.join(SOURCE)).unwrap(), PAYLOAD);
}

fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path).unwrap_err().kind(),
		io::ErrorKind::NotFound
	);
}

fn copy_block_reason(
	error: &DarwinCopyError,
	stage_path: &Path,
	before: &fs::Metadata,
	modified: SystemTime,
) -> Option<&'static str> {
	if error.progress() != PublicationProgress::Private {
		return None;
	}
	if has_extended_attributes(error) {
		return Some("strict-extended-attributes");
	}
	let DarwinCopyFailure::Transfer(transfer) = error.failure() else {
		return None;
	};
	(matches!(
		transfer.failure(),
		StageTransferFailure::ApplyMetadata(StageError::Mounted(_))
	) && before.created().is_ok_and(|birth| modified < birth)
		&& fs::symlink_metadata(stage_path).is_ok_and(|current| {
			current.dev() == before.dev()
				&& current.ino() == before.ino()
				&& current.created().is_ok_and(|birth| birth == modified)
		}))
	.then_some("observed-darwin-stage-birth-adjustment")
}

fn has_extended_attributes(mut error: &(dyn Error + 'static)) -> bool {
	loop {
		if matches!(
			error.downcast_ref::<BasicMetadataError>(),
			Some(BasicMetadataError::ExtendedAttributes)
		) {
			return true;
		}
		let Some(cause) = error.source() else {
			return false;
		};
		error = cause;
	}
}
