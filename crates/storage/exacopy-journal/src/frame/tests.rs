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

#[test]
fn allocated_windows_capture_kinds_round_trip_at_43_and_44() {
	for (code, kind) in [
		(43_u16, FrameKind::WindowsCapturePrepared),
		(44, FrameKind::WindowsCaptureRange),
	] {
		let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
		writer.append(kind, &[]).expect("known allocated kind");
		let bytes = writer.into_inner();
		assert_eq!(bytes[10..12], code.to_le_bytes());
		let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
		assert_eq!(reader.next_frame().unwrap().unwrap().kind(), kind);
	}
	assert_eq!(FrameKind::from_code(45, false), None);
}
