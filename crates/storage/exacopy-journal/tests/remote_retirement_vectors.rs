//! Compare kind 39 to the independent Python CBOR and portable C framing oracle.

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase as Phase, replay_remote_finalization,
};
use exacopy_journal::remote_download::retirement::RemoteCaptureRetired;
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadError, RemoteDownloadOwnerRecord,
};
use exacopy_journal::{LinuxFileIdentity, OwnerProfileId};

const JOURNAL: &str = include_str!("remote_finalization/retirement_journal.hex");
const OWNER: &str = include_str!("remote_finalization/owner.hex");
const QUALIFICATION: [u8; 32] = [0x71; 32];
const GRANT: [u8; 32] = [0x72; 32];

fn hex(text: &str) -> Vec<u8> {
	let clean = text.split_ascii_whitespace().collect::<String>();
	let (pairs, tail) = clean.as_bytes().as_chunks::<2>();
	assert!(tail.is_empty(), "fixture must contain whole octets");
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

#[test]
fn independent_retirement_vector_matches_wire_and_exact_historical_transition() {
	let bytes = hex(JOURNAL);
	let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
	let owner = RemoteDownloadOwnerRecord::decode(&hex(OWNER), profile, &key).unwrap();
	let trust = RemoteBootstrapTrust::new(&owner, profile, &key).unwrap();

	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let (begin, frame) = loop {
		let offset = usize::try_from(reader.offset()).unwrap();
		let frame = reader
			.next_frame()
			.unwrap()
			.expect("independent transcript must include kind 39");
		if frame.kind() == FrameKind::RemoteCaptureRetired {
			break (offset, frame);
		}
	};
	let end = usize::try_from(reader.offset()).unwrap();
	assert_eq!(frame.kind().code(), 39);
	assert_eq!(frame.head().sequence(), 9);
	let record = RemoteCaptureRetired::from_frame(&frame).unwrap();
	let payload = record.encode().unwrap();
	assert_eq!(payload, frame.payload());
	let mut writer = FrameWriter::new(Vec::new(), record.predecessor());
	assert_eq!(
		writer
			.append(FrameKind::RemoteCaptureRetired, &payload)
			.unwrap(),
		frame.head()
	);
	assert_eq!(writer.into_inner(), bytes[begin..end]);

	let before = replay_remote_finalization(&bytes[..begin], &trust, QUALIFICATION, None).unwrap();
	assert_eq!(before.phase(), Phase::MetadataReady);
	assert_eq!(before.boundary().head, record.predecessor());
	assert!(before.retirements().is_empty());
	assert!(before.issue().is_none());

	let retired = replay_remote_finalization(&bytes[..end], &trust, QUALIFICATION, None).unwrap();
	assert_eq!(retired.phase(), Phase::Retired);
	assert!(retired.issue().is_none());
	let [old] = retired.retirements() else {
		panic!("one old capture must remain");
	};
	assert_eq!(old.head, frame.head());
	assert_eq!(old.seal.sequence(), 6);
	assert_eq!(old.stage, LinuxFileIdentity::new(7, 13));
	assert_eq!(old.directory, LinuxFileIdentity::new(7, 12));
	assert_eq!(old.grant_digest, GRANT);
	assert_eq!(old.qualification_digest, QUALIFICATION);

	let restarted =
		replay_remote_finalization(bytes.as_slice(), &trust, QUALIFICATION, None).unwrap();
	assert_eq!(restarted.phase(), Phase::Capture);
	assert!(restarted.issue().is_none());
	assert_eq!(restarted.retirements(), retired.retirements());
	let [previous, next] = restarted.attempts() else {
		panic!("the historical and fresh attempts must remain distinct");
	};
	assert_eq!(previous.name(), b"first-\xff");
	assert_eq!(previous.allocation(), old.allocation);
	assert_eq!(previous.prepared().unwrap().head, old.prepared);
	assert_eq!(previous.covered_extent(), 2);
	assert_eq!(next.name(), b"fresh-\xff");
	assert_eq!(next.epochs().run.get(), 2);
	assert_eq!(next.epochs().source.get(), 8);
	assert_eq!(next.covered_extent(), 0);
	assert!(next.prepared().is_none());

	let mut obsolete_profile = payload;
	assert_eq!(&obsolete_profile[..6], &[0xa8, 0, 0x83, 1, 0, 7]);
	obsolete_profile[5] = 3;
	assert_eq!(
		RemoteCaptureRetired::decode(&obsolete_profile),
		Err(RemoteDownloadError::UnsupportedVersion)
	);
}
