use std::io::{self, Write};

use super::{INCONCLUSIVE, MANAGED_ACK_BYTES, deliver, read_bounded};

#[test]
fn bounds_input_and_requires_an_exact_end() {
	assert_eq!(read_bounded(&mut &b"abc"[..], 3).unwrap(), b"abc");
	assert_eq!(read_bounded(&mut &b"abcd"[..], 3), Err("input_limit"));
	assert_eq!(read_bounded(&mut io::empty(), 3).unwrap(), b"");
}

#[test]
fn reports_delivery_uncertain_without_reissuing_the_acknowledgement() {
	let ack = [b'x'; MANAGED_ACK_BYTES];
	for accepted in [3, MANAGED_ACK_BYTES] {
		let mut output = FailingOutput {
			accepted,
			bytes: Vec::new(),
		};
		let mut stderr = Vec::new();
		assert_eq!(deliver(&ack, &mut output, &mut stderr), INCONCLUSIVE);
		assert_eq!(output.bytes, ack[..accepted]);
		assert_eq!(
			stderr,
			b"exacopy: managed sync Init delivery_uncertain; selection slot retained\n"
		);
	}

	let mut stdout = Vec::new();
	let mut stderr = Vec::new();
	assert_eq!(deliver(&ack, &mut stdout, &mut stderr), 0);
	assert_eq!(stdout, ack);
	assert!(stderr.is_empty());
}

struct FailingOutput {
	accepted: usize,
	bytes: Vec<u8>,
}

impl Write for FailingOutput {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		let left = self.accepted - self.bytes.len();
		if left == 0 {
			return Err(io::Error::other("fixture write failed"));
		}
		let length = bytes.len().min(left);
		self.bytes.extend_from_slice(&bytes[..length]);
		Ok(length)
	}

	fn flush(&mut self) -> io::Result<()> {
		Err(io::Error::other("fixture flush failed"))
	}
}
