//! Wire and independent selection checks for the managed action origin.

use exacopy_journal::frame::{
	ChainHead, FrameKind, FrameProblem, FrameReadError, FrameReader, FrameWriter,
};
use exacopy_journal::managed_action_prepared::{
	MANAGED_ACTION_PREPARED_FRAME_BYTES, MANAGED_ACTION_PREPARED_PAYLOAD_BYTES,
	ManagedActionPrepared, ManagedActionPreparedError as Error, encode_managed_action_prepared,
	match_managed_action_prepared,
};
use exacopy_journal::managed_activation_claim::{
	ManagedActivationChild, ManagedActivationPrepared,
};
use exacopy_journal::{
	ApprovedPublicPlanDigest, JournalEntryId, JournalEpoch, JournalJobId, OwnerProfileId,
	PublicPlanEntryId,
};

const BODY: &str = include_str!("../verification/managed_action_prepared/body.hex");
const FRAME: &str = include_str!("../verification/managed_action_prepared/frame.hex");
const HEAD: &str = include_str!("../verification/managed_action_prepared/frame-head.hex");

fn hex<const N: usize>(input: &str) -> [u8; N] {
	let digits: Vec<_> = input
		.chars()
		.filter(|ch| !ch.is_ascii_whitespace())
		.collect();
	assert_eq!(digits.len(), 2 * N);
	std::array::from_fn(|index| {
		let high = digits[2 * index].to_digit(16).unwrap();
		let low = digits[2 * index + 1].to_digit(16).unwrap();
		u8::try_from(high * 16 + low).unwrap()
	})
}

fn expected() -> ManagedActionPrepared {
	ManagedActionPrepared {
		enrollment: hex("151c232a31383f464d545b626970777e"),
		allocation: hex("363d444b525960676e757c838a91989f"),
		profile: OwnerProfileId::from_bytes(hex("575e656c737a81888f969da4abb2b9c0")).unwrap(),
		pair: hex("0186a634128e7aec9c6742a66e10b2cd"),
		predecessor_generation: 1,
		predecessor_root: hex("787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51"),
		review_parent: hex("99a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b72"),
		reviewed_action: hex("bac1c8cfd6dde4ebf2f900070e151c23"),
		child: ManagedActivationChild {
			public_plan: ApprovedPublicPlanDigest::from_bytes(hex(
				"dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4",
			)),
			public_entry: PublicPlanEntryId::from_bytes(hex("fc030a11181f262d343b424950575e65"))
				.unwrap(),
			private_plan: hex("1d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6"),
			job: JournalJobId::from_bytes(hex("019a4019d27373d3a68140fc89725c12")).unwrap(),
			entry: JournalEntryId::from_bytes(hex("3e454c535a61686f767d848b9299a0a7")),
			epoch: JournalEpoch::new(0xa1b2_c3d4_e5f6_0718),
		},
		slot: hex("5f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a3138"),
		segment: hex("80878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b5259"),
	}
}

fn boundary() -> ManagedActivationPrepared {
	ManagedActivationPrepared {
		head: ChainHead::after(1, hex(HEAD)).unwrap(),
		extent: 432,
	}
}

fn reseal(frame: &mut [u8; 432]) -> ManagedActivationPrepared {
	let crc = crc32c::crc32c(&frame[..396]);
	frame[396..400].copy_from_slice(&crc.to_le_bytes());
	let mut preimage = b"ExaCopy/journal-record/v1\0".to_vec();
	preimage.extend_from_slice(&frame[..400]);
	let digest = *blake3::hash(&preimage).as_bytes();
	frame[400..].copy_from_slice(&digest);
	let sequence = u64::from_le_bytes(frame[16..24].try_into().unwrap());
	ManagedActivationPrepared {
		head: ChainHead::after(sequence, digest).unwrap(),
		extent: 432,
	}
}

fn reframe(body: &[u8; 340]) -> ([u8; 432], ManagedActivationPrepared) {
	let mut frame = hex::<432>(FRAME);
	frame[56..396].copy_from_slice(body);
	let boundary = reseal(&mut frame);
	(frame, boundary)
}

#[test]
fn managed_action_prepared_matches_independent_body_frame_and_boundary() {
	let expected = expected();
	let body = hex::<340>(BODY);
	let frame = hex::<432>(FRAME);
	assert_eq!(MANAGED_ACTION_PREPARED_PAYLOAD_BYTES, body.len());
	assert_eq!(MANAGED_ACTION_PREPARED_FRAME_BYTES, frame.len());
	assert_eq!(encode_managed_action_prepared(&expected).unwrap(), body);
	let mut reconstructed = frame;
	assert_eq!(reseal(&mut reconstructed), boundary());
	assert_eq!(reconstructed, frame);
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	let head = writer
		.append(FrameKind::ManagedActionPrepared, &body)
		.unwrap();
	assert_eq!(head, boundary().head);
	assert_eq!(writer.into_inner().as_slice(), frame.as_slice());
	assert_eq!(
		match_managed_action_prepared(&frame, &expected, boundary()).unwrap(),
		boundary(),
	);
}

#[test]
fn managed_action_prepared_refuses_nonexact_extent_and_envelope() {
	let expected = expected();
	let selected = boundary();
	let golden = hex::<432>(FRAME);
	for end in 0..golden.len() {
		assert!(matches!(
			match_managed_action_prepared(&golden[..end], &expected, selected),
			Err(Error::Length)
		));
	}
	let mut trailing = golden.to_vec();
	trailing.push(0);
	assert!(matches!(
		match_managed_action_prepared(&trailing, &expected, selected),
		Err(Error::Length)
	));
	for claimed in [0_u32, 339, 341, u32::MAX] {
		let mut damaged = golden;
		damaged[12..16].copy_from_slice(&claimed.to_le_bytes());
		assert!(matches!(
			match_managed_action_prepared(&damaged, &expected, selected),
			Err(Error::PayloadLength)
		));
	}
	for (index, expected_problem) in [
		(0, FrameProblem::Magic),
		(8, FrameProblem::UnsupportedVersion(0)),
		(396, FrameProblem::Checksum),
		(431, FrameProblem::Digest),
	] {
		let mut damaged = golden;
		damaged[index] ^= 1;
		assert!(matches!(
			match_managed_action_prepared(&damaged, &expected, selected),
			Err(Error::Frame(FrameReadError::Corrupt { offset: 0, problem }))
				if problem == expected_problem
		));
	}
	let mut unknown_kind = golden;
	unknown_kind[10..12].copy_from_slice(&46_u16.to_le_bytes());
	assert!(matches!(
		match_managed_action_prepared(&unknown_kind, &expected, selected),
		Err(Error::Frame(FrameReadError::Corrupt {
			problem: FrameProblem::UnsupportedKind(46),
			..
		}))
	));
	let mut wrong_kind = golden;
	wrong_kind[10..12].copy_from_slice(&1_u16.to_le_bytes());
	let recomputed = reseal(&mut wrong_kind);
	for valid_checksum in [true, false] {
		if !valid_checksum {
			wrong_kind[396] ^= 1;
		}
		assert!(matches!(
			match_managed_action_prepared(&wrong_kind, &expected, recomputed),
			Err(Error::Kind)
		));
	}
	for (index, value, problem) in [
		(16, 2, FrameProblem::Sequence(2)),
		(24, 1, FrameProblem::PreviousDigest),
	] {
		let mut wrong_chain = golden;
		wrong_chain[index] = value;
		let recomputed = reseal(&mut wrong_chain);
		assert!(matches!(
			match_managed_action_prepared(&wrong_chain, &expected, recomputed),
			Err(Error::Frame(FrameReadError::Corrupt { problem: actual, .. })) if actual == problem
		));
	}
}

#[test]
fn managed_action_prepared_checks_semantics_under_valid_envelopes() {
	let expected = expected();
	let golden = hex::<340>(BODY);
	for (at, len) in [
		(4, 16),
		(20, 16),
		(36, 16),
		(52, 16),
		(68, 8),
		(76, 32),
		(108, 32),
		(140, 16),
		(156, 32),
		(188, 16),
		(204, 32),
		(236, 16),
		(252, 16),
		(268, 8),
		(276, 32),
		(308, 32),
	] {
		let mut invalid = golden;
		invalid[at..at + len].fill(0);
		let (bytes, selected) = reframe(&invalid);
		assert!(
			matches!(
				match_managed_action_prepared(&bytes, &expected, selected),
				Err(Error::Field)
			),
			"zero field at {at}"
		);
	}
	for (from, to, len) in [(4, 20, 16), (276, 308, 32)] {
		let mut alias = golden;
		alias.copy_within(from..from + len, to);
		let (bytes, selected) = reframe(&alias);
		assert!(matches!(
			match_managed_action_prepared(&bytes, &expected, selected),
			Err(Error::Field)
		));
	}
	for at in [0, 1] {
		let mut body = golden;
		body[at] ^= 1;
		let (bytes, selected) = reframe(&body);
		assert!(matches!(
			match_managed_action_prepared(&bytes, &expected, selected),
			Err(Error::UnsupportedVersion)
		));
	}
	for bit in 0..16 {
		let mut body = golden;
		body[2..4].copy_from_slice(&(1_u16 << bit).to_le_bytes());
		let (bytes, selected) = reframe(&body);
		assert!(matches!(
			match_managed_action_prepared(&bytes, &expected, selected),
			Err(Error::UnsupportedFeatures)
		));
	}
	for (at, value) in [(58, 0x4a), (60, 0x0c), (68, 2), (242, 0x43), (244, 0x26)] {
		let mut invalid = golden;
		invalid[at] = value;
		let (bytes, selected) = reframe(&invalid);
		assert!(
			matches!(
				match_managed_action_prepared(&bytes, &expected, selected),
				Err(Error::Field)
			),
			"nonzero malformed field at {at}",
		);
	}
	let mut wrong_generation = expected;
	wrong_generation.predecessor_generation = 2;
	assert!(matches!(
		encode_managed_action_prepared(&wrong_generation),
		Err(Error::Field)
	));
	assert!(matches!(
		match_managed_action_prepared(&hex::<432>(FRAME), &wrong_generation, boundary()),
		Err(Error::Field)
	));
}

#[test]
fn managed_action_prepared_requires_independently_selected_fields_and_boundary() {
	let expected = expected();
	let golden = hex::<340>(BODY);
	// Keep each changed field structurally valid so the independent selection decides.
	for at in [
		4, 20, 36, 52, 76, 108, 140, 156, 188, 204, 236, 252, 268, 276, 308,
	] {
		let mut body = golden;
		body[at] ^= 1;
		let (bytes, recomputed) = reframe(&body);
		assert!(
			matches!(
				match_managed_action_prepared(&bytes, &expected, recomputed),
				Err(Error::SelectionMismatch)
			),
			"selection at {at}"
		);
	}
	let mut replacement = expected.clone();
	replacement.review_parent[0] ^= 1;
	let (bytes, recomputed) = reframe(&encode_managed_action_prepared(&replacement).unwrap());
	assert_ne!(recomputed, boundary());
	assert!(matches!(
		match_managed_action_prepared(&bytes, &replacement, boundary()),
		Err(Error::BoundaryMismatch)
	));
	let expected_boundary = boundary();
	let frame = hex::<432>(FRAME);
	for wrong in [
		ManagedActivationPrepared {
			extent: 431,
			..expected_boundary
		},
		ManagedActivationPrepared {
			head: ChainHead::after(2, expected_boundary.head.digest()).unwrap(),
			..expected_boundary
		},
	] {
		assert!(matches!(
			match_managed_action_prepared(&frame, &expected, wrong),
			Err(Error::BoundaryMismatch)
		));
	}
}

#[test]
fn ordinary_reader_refuses_managed_kind_at_every_complete_discriminator_cut() {
	let origin = hex::<432>(FRAME);
	let mut ordinary_writer = FrameWriter::new(Vec::new(), ChainHead::start());
	let prefix_head = ordinary_writer
		.append(FrameKind::JobPrepared, b"ordinary envelope")
		.unwrap();
	let prefix = ordinary_writer.into_inner();

	let mut managed_writer = FrameWriter::new(Vec::new(), prefix_head);
	managed_writer
		.append(FrameKind::ManagedActionPrepared, &hex::<340>(BODY))
		.unwrap();
	let suffix = managed_writer.into_inner();

	for (prefix, head, managed) in [
		(b"".as_slice(), ChainHead::start(), origin.as_slice()),
		(prefix.as_slice(), prefix_head, suffix.as_slice()),
	] {
		let offset = u64::try_from(prefix.len()).unwrap();
		for cut in 1..=managed.len() {
			let wire = [prefix, &managed[..cut]].concat();
			let mut reader = FrameReader::new(wire.as_slice(), ChainHead::start());
			if !prefix.is_empty() {
				assert_eq!(reader.next_frame().unwrap().unwrap().head(), head);
			}
			let refused = reader.next_frame();
			if cut < 12 {
				assert!(
					matches!(
						refused,
						Err(FrameReadError::TornTail { offset: found, bytes_read })
							if found == offset && bytes_read == cut
					),
					"cut {cut} after byte {offset}"
				);
			} else {
				assert!(
					matches!(
						refused,
						Err(FrameReadError::Corrupt { offset: found, problem: FrameProblem::UnsupportedKind(45) })
							if found == offset
					),
					"cut {cut} after byte {offset}"
				);
			}
			assert_eq!(reader.head(), head);
			assert_eq!(reader.offset(), offset);
			assert!(matches!(reader.next_frame(), Err(FrameReadError::Stopped)));
		}
	}
}
