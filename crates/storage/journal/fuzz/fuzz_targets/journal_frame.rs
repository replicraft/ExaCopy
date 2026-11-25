//! Checks bounded sequential consumption and lossless re-encoding of accepted envelopes.
#![no_main]
#![forbid(unsafe_code)]

use std::io::{self, Read};

use libfuzzer_sys::fuzz_target;

use exacopy_journal::frame::{
	ChainHead, Frame, FrameKind, FrameReadError, FrameReader, FrameWriter,
};
use exacopy_journal::{
	MAX_RANGE_PAGE_BYTES, RangeCheckpoint, RangePage, RangeResumeStarted, RecoveryDecision,
	RecoveryStarted, RetainedPublicationDecision,
};

const WIRE_PAYLOAD_LIMIT: usize = 1_048_576;
const WIRE_HEADER_BYTES: usize = 56;
const WIRE_OVERHEAD_BYTES: usize = 92;

struct BoundedRead<'a>(&'a [u8]);

impl Read for BoundedRead<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		assert!(
			buffer.len() <= WIRE_PAYLOAD_LIMIT,
			"decoder requested {} bytes from one allocation",
			buffer.len()
		);
		self.0.read(buffer)
	}
}

fuzz_target!(|input: &[u8]| {
	check_recovery_payload(input);
	if let Some(resume) = check_recovery_start_payload(input) {
		check_resume_envelope(input, resume);
	}
	if let Ok(checkpoint) = RangeCheckpoint::decode(input) {
		assert_eq!(checkpoint.encode(), input);
	}
	if let Ok(page) = RangePage::decode(input) {
		assert!(input.len() <= MAX_RANGE_PAGE_BYTES);
		assert_eq!(page.encode(), input);
		assert_eq!(page.reference().byte_length(), input.len());
		assert_eq!(page.reference().ordinal(), page.ordinal());
	}
	let mut reader = FrameReader::new(BoundedRead(input), ChainHead::start());
	let mut consumed = 0;
	let mut previous = ChainHead::start();
	loop {
		match reader.next_frame() {
			Ok(Some(frame)) => {
				let sequence = frame.head().sequence();
				assert!(sequence > previous.sequence());
				assert_eq!(frame.previous_digest(), previous.digest());
				let payload_bytes = frame.payload().len();
				assert!(payload_bytes <= WIRE_PAYLOAD_LIMIT);
				let end = consumed + WIRE_OVERHEAD_BYTES + payload_bytes;
				assert_eq!(
					reader.offset(),
					u64::try_from(end).expect("fuzz input size")
				);
				assert_eq!(
					frame.payload(),
					&input[consumed + WIRE_HEADER_BYTES..][..payload_bytes]
				);

				let anchor = if previous == ChainHead::start() {
					assert_eq!(sequence, 1);
					previous
				} else {
					// A reader accepts any strictly increasing sequence. The writer increments by one.
					ChainHead::after(sequence - 1, previous.digest()).expect("nonzero anchor")
				};
				let mut writer = FrameWriter::new(Vec::new(), anchor);
				assert_eq!(
					writer
						.append(frame.kind(), frame.payload())
						.expect("re-encode accepted frame"),
					frame.head()
				);
				assert_eq!(writer.into_inner().as_slice(), &input[consumed..end]);
				match frame.kind() {
					FrameKind::RangeCheckpoint => {
						if let Ok(checkpoint) = RangeCheckpoint::from_frame(&frame) {
							assert_eq!(checkpoint.encode(), frame.payload());
						}
					}
					FrameKind::RecoveryStarted => {
						if let Some(resume) = check_recovery_start_payload(frame.payload()) {
							let preceding = resume.evidence().preceding;
							let frame_matches = preceding == previous
								&& preceding.sequence().checked_add(1) == Some(sequence);
							assert_eq!(
								RangeResumeStarted::from_frame(&frame).is_ok(),
								frame_matches
							);
							assert!(RecoveryStarted::from_frame(&frame).is_err());
						}
					}
					FrameKind::RecoveryDecision => check_recovery_payload(frame.payload()),
					_ => {}
				}
				consumed = end;
				previous = frame.head();
				assert_eq!(reader.head(), previous);
			}
			Ok(None) => {
				assert_eq!(consumed, input.len());
				assert!(reader.next_frame().expect("clean EOF is stable").is_none());
				break;
			}
			Err(error) => {
				assert_eq!(
					reader.offset(),
					u64::try_from(consumed).expect("fuzz input size")
				);
				assert_eq!(reader.head(), previous);
				assert!(matches!(reader.next_frame(), Err(FrameReadError::Stopped)));
				match error {
					FrameReadError::Corrupt { offset, .. } => {
						assert_eq!(offset, reader.offset());
					}
					FrameReadError::TornTail { offset, bytes_read } => {
						assert_eq!(offset, reader.offset());
						assert_eq!(consumed + bytes_read, input.len());
						assert_ne!(bytes_read, 0);
					}
					FrameReadError::Io { .. } | FrameReadError::Stopped => {
						panic!("unexpected error for in-memory input: {error}");
					}
				}
				break;
			}
		}
	}
});

fn check_recovery_payload(input: &[u8]) {
	if let Ok(retained) = RetainedPublicationDecision::decode(input) {
		assert_eq!(retained.encode(), input);
		assert!(RecoveryDecision::decode(input).is_err());
	}
	if let Ok(published) = RecoveryDecision::decode(input) {
		assert_eq!(published.encode(), input);
		assert!(RetainedPublicationDecision::decode(input).is_err());
	}
}

fn check_recovery_start_payload(input: &[u8]) -> Option<RangeResumeStarted> {
	if let Ok(start) = RecoveryStarted::decode(input) {
		assert_eq!(start.encode(), input);
		assert!(RangeResumeStarted::decode(input).is_err());
	}
	let resume = RangeResumeStarted::decode(input).ok()?;
	assert_eq!(resume.encode(), input);
	assert!(RecoveryStarted::decode(input).is_err());
	Some(resume)
}

fn check_resume_envelope(payload: &[u8], resume: RangeResumeStarted) {
	let preceding = resume.evidence().preceding;
	let Some(sequence) = preceding.sequence().checked_add(1) else {
		return;
	};
	let frame = write_and_read_start(preceding, payload);
	assert_eq!(frame.head().sequence(), sequence);
	assert_eq!(RangeResumeStarted::from_frame(&frame), Ok(resume));
	assert!(RecoveryStarted::from_frame(&frame).is_err());

	let mut other_digest = preceding.digest();
	other_digest[0] ^= 1;
	if let Some(other_head) = ChainHead::after(preceding.sequence(), other_digest) {
		let other_frame = write_and_read_start(other_head, payload);
		assert!(RangeResumeStarted::from_frame(&other_frame).is_err());
	}
}

fn write_and_read_start(anchor: ChainHead, payload: &[u8]) -> Frame {
	let mut writer = FrameWriter::new(Vec::new(), anchor);
	writer
		.append(FrameKind::RecoveryStarted, payload)
		.expect("write the bounded recovery start");
	FrameReader::new(BoundedRead(&writer.into_inner()), anchor)
		.next_frame()
		.expect("read the generated recovery envelope")
		.expect("generated recovery start is present")
}
