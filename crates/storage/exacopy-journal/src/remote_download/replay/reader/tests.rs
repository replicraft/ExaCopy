use ed25519_dalek::SigningKey;

use crate::OwnerProfileId;
use crate::frame::{FrameProblem, FrameReadError, FrameWriter};
use crate::remote_download::RemoteDownloadBody;
use crate::remote_download::replay::RemoteReplayState;

use super::*;

fn fixture() -> (RemoteDownloadOwnerRecord, Vec<u8>) {
	let text = include_str!(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/tests/remote_download/owner.hex"
	));
	let ascii = text.split_ascii_whitespace().collect::<String>();
	let (pairs, remainder) = ascii.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty(), "fixture must contain complete octets");
	let owner_bytes: Vec<u8> = pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect();
	let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
	let key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	let owner = RemoteDownloadOwnerRecord::decode(&owner_bytes, profile, &key).unwrap();
	let manifest = owner.manifest();
	let context = RemoteDownloadContext {
		owner: owner.digest(),
		job: manifest.job,
		entry: manifest.scope.entry,
	};
	let body = RemoteDownloadBody::JobPrepared {
		scope: manifest.scope.digest().unwrap(),
	};
	let encoded = RemoteDownloadRecord::new(context, None, body)
		.unwrap()
		.encode()
		.unwrap();
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	writer.append(body.kind(), &encoded).unwrap();
	(owner, writer.into_inner())
}

#[test]
fn accepts_exact_segment_limit_and_refuses_one_byte_over() {
	let (owner, bytes) = fixture();
	let limit = u64::try_from(bytes.len()).unwrap();
	let exact = replay(bytes.as_slice(), &owner, limit, 4).unwrap();
	assert!(matches!(exact.state(), RemoteReplayState::JobPrepared));
	assert_eq!(exact.boundary().offset, limit);

	let over = replay(bytes.as_slice(), &owner, limit - 1, 4).unwrap();
	assert!(matches!(
		over.state(),
		RemoteReplayState::ReconciliationRequired(RemoteReplayIssue::SegmentLimit)
	));
	assert_eq!(over.boundary().offset, 0);

	let mut trailing = bytes;
	trailing.push(0);
	let over = replay(trailing.as_slice(), &owner, limit, 4).unwrap();
	assert!(matches!(
		over.state(),
		RemoteReplayState::ReconciliationRequired(RemoteReplayIssue::SegmentLimit)
	));
	assert_eq!(over.boundary(), exact.boundary());
}

struct Interrupted<'calls>(&'calls Cell<usize>);

impl Read for Interrupted<'_> {
	fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
		self.0.set(self.0.get() + 1);
		Err(io::ErrorKind::Interrupted.into())
	}
}

#[test]
fn persistent_read_error_preserves_the_last_verified_prefix() {
	let (owner, bytes) = fixture();
	let calls = Cell::new(0);
	let limit = u64::try_from(bytes.len()).unwrap() + 10;
	let input = bytes.as_slice().chain(Interrupted(&calls));
	let stopped = replay(input, &owner, limit, 4).unwrap();
	assert!(matches!(
		stopped.state(),
		RemoteReplayState::ReconciliationRequired(RemoteReplayIssue::Framing(
			FrameReadError::Io { .. }
		))
	));
	assert_eq!(
		stopped.boundary().offset,
		u64::try_from(bytes.len()).unwrap()
	);
	assert_eq!(calls.get(), usize::from(MAX_INTERRUPTED_RETRIES) + 1);
}

#[test]
fn damaged_frame_stops_at_the_previous_accepted_boundary() {
	let (owner, mut bytes) = fixture();
	*bytes.last_mut().unwrap() ^= 0x80;
	let stopped = replay(bytes.as_slice(), &owner, bytes.len() as u64, 4).unwrap();
	assert!(matches!(
		stopped.state(),
		RemoteReplayState::ReconciliationRequired(RemoteReplayIssue::Framing(
			FrameReadError::Corrupt {
				problem: FrameProblem::Digest,
				offset: 0
			}
		))
	));
	assert_eq!(stopped.boundary().head, ChainHead::start());
	assert_eq!(stopped.boundary().offset, 0);
}
