//! Independent canonical vectors and refusal controls for explicit SFTP finalization.

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::remote_download::finalization::{
	MAX_REMOTE_FINALIZATION_BYTES, MAX_REMOTE_RECEIPT_BYTES, RemoteDownloadReceipt,
	RemoteFinalizationBody as Body, RemoteFinalizationRecord, RemotePublicationObservation,
	RemoteReceiptFrames, RemoteReceiptOutcome,
};
use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::{
	RemoteDownloadError as Error, RemoteDownloadOwnerRecord, RemoteDownloadRecord,
};
use exacopy_journal::{LinuxFileIdentity, OwnerProfileId};

const PREFIX_BYTES: &str = include_str!("remote_finalization/journal.hex");
const OWNER_BYTES: &str = include_str!("remote_finalization/owner.hex");
const RECEIPT_BYTES: &str = include_str!("remote_finalization/receipt.hex");

fn hex(text: &str) -> Vec<u8> {
	let text = text.split_ascii_whitespace().collect::<String>();
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn trace() -> Vec<Frame> {
	let bytes = hex(PREFIX_BYTES);
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let mut frames = Vec::new();
	while let Some(frame) = reader.next_frame().unwrap() {
		frames.push(frame);
	}
	assert_eq!(frames.len(), 10);
	frames
}

fn owner() -> RemoteDownloadOwnerRecord {
	let bytes = hex(OWNER_BYTES);
	let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
	let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	RemoteDownloadOwnerRecord::decode(&bytes, profile, &key).unwrap()
}

fn bundle(frames: &[Frame]) -> RemoteReceiptFrames<'_> {
	RemoteReceiptFrames {
		allocation: &frames[1],
		prepared: &frames[2],
		seal: &frames[3],
		verification: &frames[4],
		metadata: &frames[5],
		intent: &frames[6],
		observed: &frames[7],
		durability: &frames[8],
	}
}

fn framed_payload(head: ChainHead, kind: FrameKind, payload: &[u8]) -> Frame {
	let mut writer = FrameWriter::new(Vec::new(), head);
	writer.append(kind, payload).unwrap();
	let bytes = writer.into_inner();
	FrameReader::new(bytes.as_slice(), head)
		.next_frame()
		.unwrap()
		.unwrap()
}

#[test]
fn independent_finalization_vectors_round_trip_and_bind_receipt() {
	let frames = trace();
	let owner = owner();
	for frame in &frames[3..] {
		let record = RemoteFinalizationRecord::from_frame(frame).unwrap();
		assert_eq!(record.body().kind(), frame.kind());
		assert_eq!(record.encode().unwrap(), frame.payload());
		assert_eq!(
			RemoteDownloadRecord::decode(frame.payload()),
			Err(Error::UnsupportedVersion)
		);
	}
	let receipt_bytes = hex(RECEIPT_BYTES);
	let from_frames = RemoteDownloadReceipt::from_frames(&owner, bundle(&frames)).unwrap();
	let parsed = RemoteDownloadReceipt::decode(&receipt_bytes).unwrap();
	assert_eq!(from_frames, parsed);
	assert_eq!(parsed.encode().unwrap(), receipt_bytes);
	assert_eq!(
		parsed.digest().unwrap().as_bytes().as_slice(),
		hex(include_str!("remote_finalization/receipt_digest.hex"))
	);
	assert_eq!(parsed.omissions(), SftpDataOnlyV1::omissions());
	assert_eq!(
		parsed.outcome(),
		RemoteReceiptOutcome::PublishedWithOmissions
	);
	assert_eq!(parsed.allocation(), frames[1].head());
	assert_eq!(parsed.binding().prepared, frames[2].head());
	assert_eq!(parsed.durability(), frames[8].head());
	assert_eq!(parsed.records().len(), 6);
	assert!(matches!(
		parsed.records().nth(3).unwrap().1.body(),
		Body::PublishIntent { target, .. }
		if target.component.as_bytes().len() == 255 && target.component.as_bytes()[254] == 0xff
	));
	parsed
		.validate_evidence(&owner, bundle(&frames), &frames[9])
		.unwrap();
}

#[test]
fn policy_vector_binds_every_omission_code() {
	assert_eq!(
		SftpDataOnlyV1::descriptor().as_slice(),
		hex(include_str!("remote_finalization/policy_descriptor.hex"))
	);
	assert_eq!(
		SftpDataOnlyV1::digest().as_slice(),
		hex(include_str!("remote_finalization/policy_digest.hex"))
	);
	assert_eq!(
		owner().manifest().scope.metadata_policy,
		SftpDataOnlyV1::digest()
	);
}

#[test]
fn bounds_versions_predecessors_and_canonical_omissions_are_checked() {
	let frames = trace();
	let seal = &frames[3];
	let predecessor = frames[2].head();
	let forged = ChainHead::after(predecessor.sequence() + 1, predecessor.digest()).unwrap();
	let skipped = framed_payload(forged, seal.kind(), seal.payload());
	assert_eq!(
		RemoteFinalizationRecord::from_frame(&skipped),
		Err(Error::FrameBinding)
	);
	let wrong_kind = framed_payload(predecessor, FrameKind::MetadataRecorded, seal.payload());
	assert_eq!(
		RemoteFinalizationRecord::from_frame(&wrong_kind),
		Err(Error::FrameBinding)
	);
	let wrong_digest = ChainHead::after(predecessor.sequence(), [0x61; 32]).unwrap();
	let substituted = framed_payload(wrong_digest, seal.kind(), seal.payload());
	assert_eq!(
		RemoteFinalizationRecord::from_frame(&substituted),
		Err(Error::FrameBinding)
	);
	assert_eq!(
		RemoteFinalizationRecord::decode(&[0; MAX_REMOTE_FINALIZATION_BYTES + 1]),
		Err(Error::Length)
	);
	assert_eq!(
		RemoteDownloadReceipt::decode(&[0; MAX_REMOTE_RECEIPT_BYTES + 1]),
		Err(Error::Length)
	);
	let mut bytes = seal.payload().to_vec();
	bytes[5] = 1;
	assert_eq!(
		RemoteFinalizationRecord::decode(&bytes),
		Err(Error::UnsupportedVersion)
	);
	let bytes = seal.payload();
	for cut in 0..bytes.len() {
		assert!(
			RemoteFinalizationRecord::decode(&bytes[..cut]).is_err(),
			"cut {cut}"
		);
	}
	let mut bytes = frames[5].payload().to_vec();
	let omission_end = bytes.len() - 1;
	bytes[omission_end] = 9;
	assert!(RemoteFinalizationRecord::decode(&bytes).is_err());
	let mut receipt = hex(RECEIPT_BYTES);
	receipt.push(0);
	assert_eq!(
		RemoteDownloadReceipt::decode(&receipt),
		Err(Error::NonCanonical)
	);
}

#[test]
fn forged_output_identity_conflict_or_wrong_preparation_has_no_receipt() {
	let frames = trace();
	let owner = owner();
	let mut evidence = bundle(&frames);
	let exact = RemoteFinalizationRecord::from_frame(evidence.observed).unwrap();
	assert_eq!(
		RemoteFinalizationRecord::new(
			exact.binding(),
			exact.predecessor(),
			Body::PublishObserved(RemotePublicationObservation::Published(
				LinuxFileIdentity::new(7, 99)
			))
		),
		Err(Error::Binding)
	);
	let conflict = RemoteFinalizationRecord::new(
		exact.binding(),
		exact.predecessor(),
		Body::PublishObserved(RemotePublicationObservation::Conflict),
	)
	.unwrap();
	let conflict = framed_payload(
		exact.predecessor(),
		FrameKind::PublishObserved,
		&conflict.encode().unwrap(),
	);
	evidence.observed = &conflict;
	assert_eq!(
		RemoteDownloadReceipt::from_frames(&owner, evidence),
		Err(Error::FrameBinding)
	);
	let old = RemoteFinalizationRecord::from_frame(evidence.durability).unwrap();
	let relinked =
		RemoteFinalizationRecord::new(old.binding(), conflict.head(), old.body()).unwrap();
	let durability = framed_payload(
		conflict.head(),
		FrameKind::DurabilityRecorded,
		&relinked.encode().unwrap(),
	);
	evidence.durability = &durability;
	assert_eq!(
		RemoteDownloadReceipt::from_frames(&owner, evidence),
		Err(Error::Binding)
	);
	let mut evidence = bundle(&frames);
	evidence.allocation = &frames[0];
	assert_eq!(
		RemoteDownloadReceipt::from_frames(&owner, evidence),
		Err(Error::FrameBinding)
	);
	let bytes = hex(RECEIPT_BYTES);
	let receipt = RemoteDownloadReceipt::decode(&bytes).unwrap();
	let wrong_commit = RemoteFinalizationRecord::new(
		receipt.binding(),
		receipt.durability(),
		Body::ReceiptCommitted {
			digest: exacopy_journal::remote_download::finalization::RemoteReceiptDigest::from_bytes(
				[0x77; 32],
			),
		},
	)
	.unwrap();
	let wrong_commit = framed_payload(
		receipt.durability(),
		FrameKind::ReceiptCommitted,
		&wrong_commit.encode().unwrap(),
	);
	assert_eq!(
		receipt.validate_evidence(&owner, bundle(&frames), &wrong_commit),
		Err(Error::FrameBinding)
	);
}
