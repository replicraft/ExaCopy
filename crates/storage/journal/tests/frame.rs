//! Independent byte vectors and I/O fault tests for the journal envelope.

use std::error::Error;
use std::io::{self, Read, Write};

use exacopy_journal::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, FrameKind, FrameProblem, FrameReadError, FrameReader,
	FrameWriteError, FrameWriter, MAX_PAYLOAD_BYTES,
};

// Formed outside the Rust codec using Python struct.pack and a bitwise Castagnoli CRC
// (checked against "123456789"), then hashed with the upstream portable C BLAKE3 implementation.
const FIRST: &[u8] = &[
	0x45, 0x58, 0x41, 0x4a, 0x4e, 0x4c, 0x30, 0x31, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x3d, 0x60, 0xd2, 0x09, 0x04, 0x39, 0x63,
	0x88, 0x30, 0xbb, 0x68, 0x8c, 0xd7, 0xab, 0x5a, 0x12, 0x12, 0x2c, 0xa4, 0xe3, 0x8b, 0xe6, 0x7d,
	0xa1, 0xba, 0xbe, 0x8e, 0x68, 0x22, 0x84, 0xe7, 0x0d, 0xa7, 0x41, 0xea, 0xa4,
];
const SECOND: &[u8] = &[
	0x45, 0x58, 0x41, 0x4a, 0x4e, 0x4c, 0x30, 0x31, 0x01, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x39, 0x63, 0x88, 0x30, 0xbb, 0x68, 0x8c,
	0xd7, 0xab, 0x5a, 0x12, 0x12, 0x2c, 0xa4, 0xe3, 0x8b, 0xe6, 0x7d, 0xa1, 0xba, 0xbe, 0x8e, 0x68,
	0x22, 0x84, 0xe7, 0x0d, 0xa7, 0x41, 0xea, 0xa4, 0xa1, 0x00, 0x01, 0xd6, 0x0d, 0xac, 0xc7, 0xcd,
	0x80, 0x17, 0x05, 0xd3, 0x93, 0xc0, 0xd2, 0x9f, 0xce, 0xe6, 0x51, 0xb7, 0xd9, 0x5b, 0x4b, 0x92,
	0x86, 0xfb, 0xac, 0xdb, 0xa1, 0x26, 0x19, 0xe5, 0x54, 0x6a, 0x27, 0x9b, 0x4f, 0x8f, 0x86,
];
const FINAL_SEQUENCE: &[u8] = &[
	0x45, 0x58, 0x41, 0x4a, 0x4e, 0x4c, 0x30, 0x31, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x04, 0x39, 0x63, 0x88, 0x30, 0xbb, 0x68, 0x8c,
	0xd7, 0xab, 0x5a, 0x12, 0x12, 0x2c, 0xa4, 0xe3, 0x8b, 0xe6, 0x7d, 0xa1, 0xba, 0xbe, 0x8e, 0x68,
	0x22, 0x84, 0xe7, 0x0d, 0xa7, 0x41, 0xea, 0xa4, 0xad, 0xc4, 0xe5, 0x3a, 0x6f, 0x80, 0xa5, 0xd7,
	0x62, 0x26, 0x3d, 0x0a, 0xef, 0xdb, 0xda, 0x47, 0xca, 0x45, 0x1c, 0x50, 0x85, 0xd7, 0x36, 0xc0,
	0xff, 0x60, 0xad, 0x8b, 0x45, 0xd3, 0x05, 0xf9, 0x78, 0xdc, 0x06, 0xea,
];

fn first_head() -> ChainHead {
	let digest = FIRST[61..].try_into().expect("fixed vector digest");
	ChainHead::after(1, digest).expect("positive sequence and nonzero digest")
}

#[test]
fn writer_and_reader_match_independent_wire_vectors() {
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	assert_eq!(
		writer
			.append(FrameKind::JobPrepared, &[0xa0])
			.expect("first append"),
		first_head()
	);
	let written_head = writer
		.append(FrameKind::PublishIntent, &[0xa1, 0, 1])
		.expect("next append");
	let expected = [FIRST, SECOND].concat();
	assert_eq!(writer.into_inner(), expected);
	assert_eq!(FRAME_OVERHEAD_BYTES, 92);

	let mut reader = FrameReader::new(expected.as_slice(), ChainHead::start());
	let first = reader
		.next_frame()
		.expect("first envelope")
		.expect("first frame");
	assert_eq!(first.kind(), FrameKind::JobPrepared);
	assert_eq!(first.head(), first_head());
	assert_eq!(first.payload(), [0xa0]);
	assert_eq!(first.previous_digest(), [0; 32]);
	assert_eq!(reader.offset(), 93);
	let second = reader
		.next_frame()
		.expect("second envelope")
		.expect("second frame");
	assert_eq!(second.kind(), FrameKind::PublishIntent);
	assert_eq!(second.head(), written_head);
	assert_eq!(second.payload(), [0xa1, 0, 1]);
	assert_eq!(second.previous_digest(), first_head().digest());
	assert_eq!(reader.offset(), 188);
	assert!(reader.next_frame().expect("clean EOF").is_none());
	assert!(reader.next_frame().expect("stable EOF").is_none());
}

#[test]
fn another_segment_retains_chain_and_allows_strict_sequence_gaps() {
	let mut reader = FrameReader::new(FINAL_SEQUENCE, first_head());
	let frame = reader
		.next_frame()
		.expect("continued chain")
		.expect("frame at maximum sequence");
	assert_eq!(frame.kind(), FrameKind::RecoveryDecision);
	assert_eq!(frame.head().sequence(), u64::MAX);
	assert_eq!(frame.previous_digest(), first_head().digest());
	assert!(frame.payload().is_empty());
	assert!(reader.next_frame().expect("clean EOF").is_none());

	let mut reversed = FrameReader::new(SECOND, frame.head());
	assert!(matches!(
		reversed.next_frame(),
		Err(FrameReadError::Corrupt {
			problem: FrameProblem::Sequence(2),
			..
		})
	));
	let mut writer = FrameWriter::new(Vec::new(), frame.head());
	assert!(matches!(
		writer.append(FrameKind::ReceiptCommitted, &[]),
		Err(FrameWriteError::SequenceExhausted)
	));
	assert_eq!(writer.head(), frame.head());
	assert!(writer.into_inner().is_empty());
	assert!(ChainHead::after(0, frame.head().digest()).is_none());
	assert!(ChainHead::after(1, [0; 32]).is_none());
}

#[test]
fn every_prefix_of_a_second_frame_is_classified_without_losing_the_first_boundary() {
	for cut in 0..=SECOND.len() {
		let bytes = [FIRST, &SECOND[..cut]].concat();
		let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
		assert!(reader.next_frame().expect("complete first frame").is_some());
		let outcome = reader.next_frame();
		match cut {
			0 => assert!(outcome.expect("clean boundary").is_none()),
			95 => assert!(outcome.expect("complete second frame").is_some()),
			_ => {
				assert!(
					matches!(outcome, Err(FrameReadError::TornTail {
					offset: 93,
					bytes_read
				}) if bytes_read == cut),
					"cut {cut}: {outcome:?}"
				);
				assert_eq!(reader.offset(), 93);
				assert_eq!(reader.head(), first_head());
				assert!(matches!(reader.next_frame(), Err(FrameReadError::Stopped)));
			}
		}
	}
}

#[test]
fn corrupt_or_unsupported_middle_frame_stops_even_with_later_magic() {
	for (index, expected) in [
		(0, FrameProblem::Magic),
		(8, FrameProblem::UnsupportedVersion(129)),
		(10, FrameProblem::UnsupportedKind(135)),
		(15, FrameProblem::PayloadTooLarge(0x8000_0003)),
		(24, FrameProblem::PreviousDigest),
		(57, FrameProblem::Checksum), // payload
		(59, FrameProblem::Checksum), // stored CRC
		(63, FrameProblem::Digest),   // stored BLAKE3
	] {
		let mut corrupted = SECOND.to_vec();
		corrupted[index] ^= 0x80;
		let bytes = [FIRST, corrupted.as_slice(), SECOND].concat();
		let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
		assert!(reader.next_frame().expect("complete first frame").is_some());
		assert!(
			matches!(
				reader.next_frame(),
				Err(FrameReadError::Corrupt { offset: 93, problem }) if problem == expected
			),
			"byte {index}, expected {expected:?}"
		);
		assert_eq!(reader.offset(), 93);
		assert_eq!(reader.head(), first_head());
		assert!(matches!(reader.next_frame(), Err(FrameReadError::Stopped)));
	}
}

#[test]
fn known_damage_in_an_incomplete_frame_is_corruption() {
	for (index, expected) in [
		(0, FrameProblem::Magic),
		(9, FrameProblem::UnsupportedVersion(257)),
		(11, FrameProblem::UnsupportedKind(263)),
		(15, FrameProblem::PayloadTooLarge(0x0100_0003)),
		(24, FrameProblem::PreviousDigest),
		(59, FrameProblem::Checksum),
		(63, FrameProblem::Digest),
	] {
		let mut damaged_prefix = SECOND[..=index].to_vec();
		damaged_prefix[index] ^= 1;
		let mut reader = FrameReader::new(damaged_prefix.as_slice(), first_head());
		assert!(
			matches!(
				reader.next_frame(),
				Err(FrameReadError::Corrupt { offset: 0, problem }) if problem == expected
			),
			"prefix ending in damaged byte {index}, expected {expected:?}"
		);
	}
}

#[test]
fn first_sequence_and_segment_anchor_are_enforced() {
	let mut second_without_anchor = FrameReader::new(SECOND, ChainHead::start());
	assert!(matches!(
		second_without_anchor.next_frame(),
		Err(FrameReadError::Corrupt {
			problem: FrameProblem::Sequence(2),
			..
		})
	));
	let mut replay_first = FrameReader::new(FIRST, first_head());
	assert!(matches!(
		replay_first.next_frame(),
		Err(FrameReadError::Corrupt {
			problem: FrameProblem::Sequence(1),
			..
		})
	));
	let foreign = ChainHead::after(1, [0xff; 32]).expect("foreign anchor");
	let mut replay_foreign = FrameReader::new(SECOND, foreign);
	assert!(matches!(
		replay_foreign.next_frame(),
		Err(FrameReadError::Corrupt {
			problem: FrameProblem::PreviousDigest,
			..
		})
	));
}

#[test]
fn payload_limit_is_checked_before_any_payload_io() {
	let mut header = FIRST[..56].to_vec();
	header[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	let mut payload = vec![0x77; MAX_PAYLOAD_BYTES + 1];
	assert!(matches!(
		writer.append(FrameKind::CredentialBlocked, &payload),
		Err(FrameWriteError::PayloadTooLarge(bytes)) if bytes == 1_048_577
	));
	assert_eq!(writer.head(), ChainHead::start());

	let refusing_reader = ShortReader {
		data: &header,
		failure_at_eof: true,
		interrupted: true,
	};
	let mut reader = FrameReader::new(refusing_reader, ChainHead::start());
	assert!(matches!(
		reader.next_frame(),
		Err(FrameReadError::Corrupt {
			offset: 0,
			problem: FrameProblem::PayloadTooLarge(u32::MAX)
		})
	));

	payload.pop();
	writer
		.append(FrameKind::CredentialBlocked, &payload)
		.expect("exact maximum");
	let wire = writer.into_inner();
	assert_eq!(wire.len(), 1_048_576 + 92);
	let mut reader = FrameReader::new(wire.as_slice(), ChainHead::start());
	let frame = reader
		.next_frame()
		.expect("bounded maximum")
		.expect("frame");
	assert_eq!(frame.kind(), FrameKind::CredentialBlocked);
	assert_eq!(frame.payload(), payload);
	assert!(reader.next_frame().expect("clean boundary").is_none());
}

#[derive(Debug)]
struct ShortReader<'a> {
	data: &'a [u8],
	failure_at_eof: bool,
	interrupted: bool,
}

impl Read for ShortReader<'_> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		if std::mem::take(&mut self.interrupted) {
			return Err(io::ErrorKind::Interrupted.into());
		}
		if self.data.is_empty() && self.failure_at_eof {
			return Err(io::ErrorKind::UnexpectedEof.into());
		}
		let maximum = bytes.len().min(3);
		self.data.read(&mut bytes[..maximum])
	}
}

#[derive(Debug)]
struct ShortWriter {
	data: Vec<u8>,
	stops_after: usize,
	interrupted: bool,
}

impl Write for ShortWriter {
	fn write(&mut self, data: &[u8]) -> io::Result<usize> {
		if std::mem::take(&mut self.interrupted) {
			return Err(io::ErrorKind::Interrupted.into());
		}
		let count = (self.stops_after - self.data.len()).min(data.len()).min(2);
		self.data.extend_from_slice(&data[..count]);
		Ok(count)
	}

	fn flush(&mut self) -> io::Result<()> {
		panic!("frame append must not claim a durability barrier");
	}
}

#[test]
fn short_io_and_interruptions_complete_an_exact_wire_frame() {
	let input = ShortReader {
		data: FIRST,
		failure_at_eof: false,
		interrupted: true,
	};
	let mut reader = FrameReader::new(input, ChainHead::start());
	assert_eq!(
		reader
			.next_frame()
			.expect("short reads")
			.expect("frame")
			.head(),
		first_head()
	);
	assert!(reader.next_frame().expect("clean EOF").is_none());

	let custom = ShortWriter {
		data: Vec::new(),
		stops_after: usize::MAX,
		interrupted: true,
	};
	let mut writer = FrameWriter::new(custom, ChainHead::start());
	assert_eq!(
		writer
			.append(FrameKind::JobPrepared, &[0xa0])
			.expect("short writes"),
		first_head()
	);
	assert_eq!(writer.into_inner().data, FIRST);
}

#[test]
fn read_errors_are_terminal_and_distinct_from_eof() {
	for cut in [0, 3, 56, 57, 61, FIRST.len()] {
		let input = ShortReader {
			data: &FIRST[..cut],
			failure_at_eof: true,
			interrupted: false,
		};
		let mut reader = FrameReader::new(input, ChainHead::start());
		let expected_offset = if cut == FIRST.len() {
			assert!(reader.next_frame().expect("complete first frame").is_some());
			93
		} else {
			0
		};
		let error = reader.next_frame().expect_err("explicit I/O error");
		assert!(matches!(
			error,
			FrameReadError::Io { offset, ref source }
				if offset == expected_offset && source.kind() == io::ErrorKind::UnexpectedEof
		));
		assert!(error.source().is_some());
		assert!(matches!(reader.next_frame(), Err(FrameReadError::Stopped)));
		assert_eq!(reader.offset(), expected_offset);
	}
}

#[test]
fn append_error_keeps_last_chain_boundary_and_blocks_further_writes() {
	for cut in 0..SECOND.len() {
		let custom = ShortWriter {
			data: Vec::new(),
			stops_after: FIRST.len() + cut,
			interrupted: false,
		};
		let mut writer = FrameWriter::new(custom, ChainHead::start());
		assert_eq!(
			writer
				.append(FrameKind::JobPrepared, &[0xa0])
				.expect("first append"),
			first_head()
		);
		let error = writer
			.append(FrameKind::PublishIntent, &[0xa1, 0, 1])
			.expect_err("injected write zero");
		assert!(
			matches!(error, FrameWriteError::Io(ref source) if source.kind() == io::ErrorKind::WriteZero)
		);
		assert!(error.source().is_some());
		assert_eq!(writer.head(), first_head());
		assert!(matches!(
			writer.append(FrameKind::PublishIntent, &[]),
			Err(FrameWriteError::Stopped)
		));
		assert_eq!(writer.into_inner().data, [FIRST, &SECOND[..cut]].concat());
	}
}

#[test]
fn single_bit_damage_never_yields_a_verified_frame() {
	for index in 0..SECOND.len() {
		for bit in 0..u8::BITS {
			let mut changed = SECOND.to_vec();
			changed[index] ^= 1_u8 << bit;
			let mut reader = FrameReader::new(changed.as_slice(), first_head());
			assert!(
				reader.next_frame().is_err(),
				"undetected single-bit change at byte {index}, bit {bit}"
			);
			assert_eq!(reader.offset(), 0);
			assert_eq!(reader.head(), first_head());
		}
	}
}

#[test]
fn published_kind_allocations_round_trip_at_their_registered_codes() {
	let registered = [
		FrameKind::JobPrepared,
		FrameKind::EntryPrepared,
		FrameKind::RangeCheckpoint,
		FrameKind::StageSealed,
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
		FrameKind::IncumbentCaptureIntent,
		FrameKind::IncumbentCaptured,
		FrameKind::SourceRetireIntent,
		FrameKind::SourceRetired,
		FrameKind::ConflictRecorded,
		FrameKind::FailureRecorded,
		FrameKind::CancellationRequested,
		FrameKind::JobCheckpoint,
		FrameKind::ReceiptCommitted,
		FrameKind::RecoveryStarted,
		FrameKind::RecoveryDecision,
		FrameKind::OwnershipTakeover,
		FrameKind::ResumeBound,
		FrameKind::ConnectionGenerationStarted,
		FrameKind::RangeRevalidated,
		FrameKind::RemoteEffectUncertain,
		FrameKind::RemoteEffectReconciled,
		FrameKind::SyncActionIntent,
		FrameKind::SyncActionObserved,
		FrameKind::SyncBaselineIntent,
		FrameKind::SyncBaselineCommitted,
		FrameKind::DeviceBindingValidated,
		FrameKind::ForwardLeaseObserved,
		FrameKind::InstallIntent,
		FrameKind::InstallObserved,
		FrameKind::InstallCommitted,
		FrameKind::CredentialBlocked,
	];
	for (code, kind) in (1_u16..=36).zip(registered) {
		let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
		writer.append(kind, &[]).expect("registered kind");
		let wire = writer.into_inner();
		assert_eq!(wire[10..12], code.to_le_bytes());
		let mut reader = FrameReader::new(wire.as_slice(), ChainHead::start());
		let frame = reader.next_frame().expect("good envelope").expect("frame");
		assert_eq!(frame.kind(), kind);
	}
}
