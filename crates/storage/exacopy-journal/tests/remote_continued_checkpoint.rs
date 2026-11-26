//! Independent vector and refusal controls for the versioned suffix checkpoint.

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::remote_download::continuation::checkpoint::{
	MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES, RemoteContinuedCheckpoint,
};
use exacopy_journal::remote_download::{RemoteDownloadError as Error, RemoteDownloadRecord};

fn hex(text: &str) -> Vec<u8> {
	let text = text.split_ascii_whitespace().collect::<String>();
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn transcript() -> Vec<u8> {
	hex(include_str!("remote_continuation/journal.hex"))
}

#[test]
fn independent_suffix_checkpoint_round_trips_and_legacy_refuses() {
	let mut bytes = transcript();
	bytes.extend(hex(include_str!("remote_continuation/checkpoint.hex")));
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let mut legacy = None;
	let mut continuation = ChainHead::start();
	for _ in 0..6 {
		let frame = reader.next_frame().unwrap().unwrap();
		if frame.kind() == FrameKind::RangeCheckpoint {
			legacy = Some(frame);
		} else if frame.kind() == FrameKind::RemoteCaptureContinued {
			continuation = frame.head();
		}
	}
	let frame = reader.next_frame().unwrap().unwrap();
	assert!(reader.next_frame().unwrap().is_none());
	let current = RemoteContinuedCheckpoint::from_frame(&frame).unwrap();
	assert_eq!(current.encode().unwrap(), frame.payload());
	assert_eq!(current.continuation(), continuation);
	assert_eq!(current.predecessor(), continuation);
	assert_eq!(current.epochs().run.get(), 2);
	assert_eq!(current.epochs().source.get(), 9);
	assert_eq!(current.range().ordinal, 1);
	assert_eq!(current.range().offset, 4);
	assert_eq!(current.range().length, 1);
	assert_eq!(
		current.range().digest.as_bytes(),
		blake3::hash(b"E").as_bytes()
	);
	assert_eq!(
		RemoteDownloadRecord::from_frame(&frame),
		Err(Error::UnsupportedVersion)
	);
	assert_eq!(
		RemoteContinuedCheckpoint::from_frame(&legacy.unwrap()),
		Err(Error::UnsupportedVersion),
	);
}

#[test]
fn incomplete_oversized_and_trailing_payloads_refuse() {
	let journal = transcript();
	let mut reader = FrameReader::new(journal.as_slice(), ChainHead::start());
	while reader.next_frame().unwrap().is_some() {}
	let suffix = hex(include_str!("remote_continuation/checkpoint.hex"));
	let frame = FrameReader::new(suffix.as_slice(), reader.head())
		.next_frame()
		.unwrap()
		.unwrap();
	let payload = frame.payload();
	for cut in 0..payload.len() {
		assert!(
			RemoteContinuedCheckpoint::decode(&payload[..cut]).is_err(),
			"cut {cut}"
		);
	}
	assert_eq!(
		RemoteContinuedCheckpoint::decode(&[0; MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES + 1]),
		Err(Error::Length),
	);
	let mut trailing = payload.to_vec();
	trailing.push(0);
	assert_eq!(
		RemoteContinuedCheckpoint::decode(&trailing),
		Err(Error::NonCanonical)
	);
}

#[test]
fn geometry_kind_and_predecessor_checks_refuse_substitutions() {
	let journal = transcript();
	let mut reader = FrameReader::new(journal.as_slice(), ChainHead::start());
	while reader.next_frame().unwrap().is_some() {}
	let suffix = hex(include_str!("remote_continuation/checkpoint.hex"));
	let frame = FrameReader::new(suffix.as_slice(), reader.head())
		.next_frame()
		.unwrap()
		.unwrap();
	let record = RemoteContinuedCheckpoint::from_frame(&frame).unwrap();
	let build = |predecessor, range| {
		RemoteContinuedCheckpoint::new(
			record.context(),
			predecessor,
			record.continuation(),
			record.epochs(),
			range,
		)
	};
	let first = record.range();
	assert_eq!(
		build(
			record.predecessor(),
			exacopy_journal::remote_download::continuation::checkpoint::RemoteContinuedRange {
				offset: 0,
				..first
			}
		),
		Err(Error::Binding),
	);
	assert_eq!(
		build(
			record.predecessor(),
			exacopy_journal::remote_download::continuation::checkpoint::RemoteContinuedRange {
				ordinal: 2,
				..first
			}
		),
		Err(Error::FrameBinding),
	);
	assert_eq!(
		build(
			ChainHead::after(record.predecessor().sequence(), [0x55; 32]).unwrap(),
			first,
		),
		Err(Error::FrameBinding),
	);
	for (kind, preceding) in [
		(FrameKind::FailureRecorded, record.predecessor()),
		(
			FrameKind::RangeCheckpoint,
			ChainHead::after(record.predecessor().sequence(), [0x55; 32]).unwrap(),
		),
	] {
		let mut writer = FrameWriter::new(Vec::new(), preceding);
		writer.append(kind, frame.payload()).unwrap();
		let bytes = writer.into_inner();
		let rewritten = FrameReader::new(bytes.as_slice(), preceding)
			.next_frame()
			.unwrap()
			.unwrap();
		assert_eq!(
			RemoteContinuedCheckpoint::from_frame(&rewritten),
			Err(Error::FrameBinding)
		);
	}
}

#[test]
fn later_ordinal_distinguishes_active_lineage_from_immediate_predecessor() {
	let mut bytes = transcript();
	bytes.extend(hex(include_str!("remote_continuation/checkpoint.hex")));
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	for _ in 0..6 {
		reader.next_frame().unwrap().unwrap();
	}
	let first_frame = reader.next_frame().unwrap().unwrap();
	let first = RemoteContinuedCheckpoint::from_frame(&first_frame).unwrap();
	let predecessor = first_frame.head();
	assert_ne!(first.continuation(), predecessor);
	let second = RemoteContinuedCheckpoint::new(
		first.context(),
		predecessor,
		first.continuation(),
		first.epochs(),
		exacopy_journal::remote_download::continuation::checkpoint::RemoteContinuedRange {
			ordinal: 2,
			offset: first.range().offset + first.range().length,
			length: 1,
			digest: exacopy_journal::StreamDigest::from_bytes(*blake3::hash(b"F").as_bytes()),
		},
	)
	.unwrap();
	let mut writer = FrameWriter::new(Vec::new(), predecessor);
	writer
		.append(FrameKind::RangeCheckpoint, &second.encode().unwrap())
		.unwrap();
	let bytes = writer.into_inner();
	let frame = FrameReader::new(bytes.as_slice(), predecessor)
		.next_frame()
		.unwrap()
		.unwrap();
	assert_eq!(RemoteContinuedCheckpoint::from_frame(&frame), Ok(second));
	assert_eq!(second.continuation(), first.continuation());
	assert_eq!(second.predecessor(), predecessor);
}
