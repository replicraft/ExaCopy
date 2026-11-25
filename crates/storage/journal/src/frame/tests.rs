use super::{ChainHead, FrameKind, FrameProblem, FrameReadError, FrameReader, FrameWriter};

#[test]
fn offset_overflow_does_not_publish_a_new_reader_boundary() {
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer
		.append(FrameKind::JobPrepared, &[])
		.expect("write empty frame");
	let wire = writer.into_inner();
	let mut reader = FrameReader::new(wire.as_slice(), ChainHead::start());
	reader.offset = u64::MAX - 91;

	assert!(matches!(
		reader.next_frame(),
		Err(FrameReadError::Corrupt {
			offset,
			problem: FrameProblem::OffsetOverflow,
		}) if offset == u64::MAX - 91
	));
	assert_eq!(reader.offset(), u64::MAX - 91);
	assert_eq!(reader.head(), ChainHead::start());
	assert!(matches!(reader.next_frame(), Err(FrameReadError::Stopped)));
}
