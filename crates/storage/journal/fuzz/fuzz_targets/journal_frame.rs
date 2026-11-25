//! Checks bounded sequential consumption and lossless re-encoding of accepted envelopes.
#![no_main]
#![forbid(unsafe_code)]

use std::io::{self, Read};

use libfuzzer_sys::fuzz_target;

use exacopy_journal::frame::{ChainHead, FrameReadError, FrameReader, FrameWriter};

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
