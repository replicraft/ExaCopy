use super::*;
use crate::macos::receipt::DarwinCopyReceipt;
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
	let fixture = Fixture::new();
	let root = fixture.root();
	let source = fixture.source(&root);
	let container = root.open_stage_directory(component(PRIVATE)).unwrap();
	let signer = SigningKey::from_bytes(&[4; 32]);
	let request = fixture.request(&source, &container, &signer);
	let plan = fixture.plan(&root, request);
	let name = JobName::from_uuid_bytes(*plan.attempt().job.as_bytes()).unwrap();
	let path = fixture.0.join(PRIVATE).join(name.to_string());
	let receipt = with_prepared_job(&plan, request, |job| {
		job.with_prepared_entry(|entry| {
			let inode = entry
				.preparation()
				.preparation()
				.stage
				.identity
				.inode()
				.get();
			let mut scratch = [0; 256];
			let receipt = entry.copy_and_publish(&mut scratch).unwrap();
			let target = fs::metadata(fixture.0.join(TARGET)).unwrap();
			assert_eq!(target.ino(), inode);
			assert_eq!(receipt.evidence().stream.identity.inode().get(), inode);
			assert_ne!(
				target.ino(),
				fs::metadata(fixture.0.join(SOURCE)).unwrap().ino()
			);
			assert!(!path.join("stage/payload").exists());
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
	.unwrap();
	let receipt = DarwinCopyReceipt::decode(&receipt).unwrap();
	let mut reader = FrameReader::new(
		File::open(path.join(FIRST_SEGMENT)).unwrap(),
		ChainHead::start(),
	);
	for kind in [
		FrameKind::JobPrepared,
		FrameKind::EntryPrepared,
		FrameKind::StageSealed,
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
	] {
		let frame = reader.next_frame().unwrap().unwrap();
		assert_eq!(kind, frame.kind());
		if kind == FrameKind::DurabilityRecorded {
			assert_eq!(receipt.durability_frame(), frame.head());
		}
	}
	let committed = reader.next_frame().unwrap().unwrap();
	assert_eq!(committed.kind(), FrameKind::ReceiptCommitted);
	assert_eq!(
		DarwinReceiptCommitted::from_frame(&committed)
			.unwrap()
			.digest(),
		receipt.digest()
	);
	assert!(reader.next_frame().unwrap().is_none());
	assert_eq!(fs::read(fixture.0.join(TARGET)).unwrap(), PAYLOAD);
	assert_eq!(fs::read(fixture.0.join(SOURCE)).unwrap(), PAYLOAD);
}
