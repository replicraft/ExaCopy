use exacopy_journal::remote_download::continuation::replay::{
	RemoteWitnessContinuationReplay, RemoteWitnessContinuationSelection,
	replay_remote_witness_continuation,
};
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	VerifiedRemoteWitnessQualification, verify_remote_witness_qualification,
};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationRouteClass, RemoteQualificationScope,
};
use exacopy_journal::remote_download::witness::{
	MAX_REMOTE_RECEIPT_READY_BYTES, MAX_REMOTE_WITNESS_INTENT_BYTES, ReceiptReadyExpectation,
	RemoteReceiptReady, RemoteWitnessIntent, RemoteWitnessIntentExpectation,
	WitnessRetentionCommitment,
};

use super::*;

struct Transcript {
	fixture: Fixture,
	qualification: VerifiedRemoteWitnessQualification,
	frames: Vec<(Frame, RemoteReplayBoundary)>,
	witness_bytes: Vec<u8>,
	tail: bool,
}

impl Transcript {
	fn read(tail: bool) -> Self {
		let fixture = Fixture::read();
		let attestor = SigningKey::from_bytes(&[0x62; 32]).verifying_key();
		let qualification = verify_remote_witness_qualification(
			&vector("qualification"),
			&RemoteContinuationQualificationTrust {
				attestor: [0x31; 16],
				attestor_key: &attestor,
				owner_key: &fixture.verify,
				scope: RemoteContinuationQualificationScope {
					common: RemoteQualificationScope {
						build: [0x61; 32],
						route: RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
						campaign_scope: [0x63; 32],
						campaign_evidence: [0x64; 32],
					},
					operation:
						RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
					coverage:
						RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
				},
			},
		)
		.unwrap();
		let bytes = vector(if tail {
			"tail-prefix"
		} else {
			"zero-through-durability"
		});
		let mut reader = FrameReader::new(bytes.as_slice(), fixture.preceding.head);
		let mut frames = Vec::new();
		while let Some(frame) = reader.next_frame().unwrap() {
			let boundary = RemoteReplayBoundary {
				head: reader.head(),
				offset: fixture.preceding.offset + reader.offset(),
			};
			frames.push((frame, boundary));
		}
		Self {
			fixture,
			qualification,
			frames,
			witness_bytes: bytes,
			tail,
		}
	}

	fn prefix(&self, index: usize) -> Vec<u8> {
		let end = usize::try_from(self.frames[index].1.offset).unwrap();
		let prior = self.fixture.prefix_end;
		[
			&self.fixture.journal[..prior],
			&self.witness_bytes[..end - prior],
		]
		.concat()
	}

	fn replay(&self, prefix: &[u8]) -> RemoteWitnessContinuationReplay {
		replay_remote_witness_continuation(
			prefix,
			&self.fixture.trust(),
			&RemoteWitnessContinuationSelection {
				initial_v1_qualification: QUALIFICATION,
				qualification: &self.qualification,
				grant_digest: [0x72; 32],
			},
		)
		.unwrap()
	}

	fn full_replay(&self) -> RemoteWitnessContinuationReplay {
		self.replay(&self.prefix(if self.tail { 2 } else { 0 }))
	}

	fn intent<'a>(
		&'a self,
		replay: &'a RemoteWitnessContinuationReplay,
	) -> RemoteWitnessIntentExpectation<'a> {
		let active = self.fixture.expectation().claims;
		let consent = WitnessRetentionCommitment::measure(
			active.context,
			active.scope,
			active.grant_digest,
			NonZeroU64::MAX,
		)
		.unwrap();
		assert_eq!(consent.approval_digest, vector("approval").as_slice());
		RemoteWitnessIntentExpectation {
			coverage: replay.complete_coverage_predecessor().unwrap(),
			qualification: &self.qualification,
			job_directory: LinuxFileIdentity::new(7, 11),
			stage_directory: LinuxFileIdentity::new(7, 12),
			consent,
		}
	}

	fn receipt(&self) -> ReceiptReadyExpectation<'_> {
		assert!(!self.tail);
		let replay = self.full_replay();
		let (frame, end) = &self.frames[1];
		let witness = self
			.fixture
			.trust()
			.from_witness_intent_frame(frame, *end, &self.intent(&replay))
			.unwrap();
		let (durability, boundary) = &self.frames[7];
		let bytes = vector("receipt");
		let digest = blake3::Hasher::new()
			.update(b"ExaCopy/linux-remote-witnessed-continued-download-receipt/v1\0")
			.update(&bytes)
			.finalize();
		assert_eq!(digest.as_bytes(), vector("receipt-digest").as_slice());
		ReceiptReadyExpectation {
			witness,
			durability,
			boundary: *boundary,
			metadata: self.frames[4].1.head,
			observed: self.frames[6].1,
			receipt: LinuxFileIdentity::new(7, 14),
			length: u16::try_from(bytes.len()).unwrap(),
			digest: *digest.as_bytes(),
		}
	}
}

fn vector(label: &str) -> Vec<u8> {
	include_str!("witness_closeout.hex")
		.lines()
		.find_map(|line| {
			let (name, value) = line.split_once(' ')?;
			(name == label).then(|| hex(value))
		})
		.unwrap()
}

fn append(
	previous: RemoteReplayBoundary,
	kind: FrameKind,
	payload: &[u8],
) -> (Frame, RemoteReplayBoundary) {
	let mut writer = FrameWriter::new(Vec::new(), previous.head);
	writer.append(kind, payload).unwrap();
	let bytes = writer.into_inner();
	let mut reader = FrameReader::new(bytes.as_slice(), previous.head);
	let frame = reader.next_frame().unwrap().unwrap();
	let boundary = RemoteReplayBoundary {
		head: reader.head(),
		offset: previous.offset + reader.offset(),
	};
	(frame, boundary)
}

#[test]
fn independent_owner_signed_intent_matches_zero_tail_and_ordinal_two() {
	for tail in [false, true] {
		let run = Transcript::read(tail);
		let trust = run.fixture.trust();
		let replay = run.full_replay();
		let expected = run.intent(&replay);
		assert_eq!(
			expected.coverage.boundary(),
			run.frames[if tail { 2 } else { 0 }].1
		);
		let payload = trust
			.sign_witness_intent(&expected, &run.fixture.key)
			.unwrap();
		let expected_bytes = if tail {
			vector("tail-witness")
		} else {
			run.frames[1].0.payload().to_vec()
		};
		assert_eq!(payload, expected_bytes);
		let (frame, end) = append(
			expected.coverage.boundary(),
			FrameKind::RemoteWitnessIntent,
			&payload,
		);
		let verified: RemoteWitnessIntent = trust
			.from_witness_intent_frame(&frame, end, &expected)
			.unwrap();
		assert_eq!(verified.boundary(), end);
		assert_eq!(verified.consent(), expected.consent);
		assert!(RemoteFinalizationRecord::decode(&payload).is_err());
	}
}

#[test]
fn signed_foreign_payloads_and_early_or_mismatched_authority_refuse() {
	let run = Transcript::read(true);
	let trust = run.fixture.trust();
	let replay = run.full_replay();
	let expected = run.intent(&replay);
	for label in [
		"wrong-profile",
		"legacy-version",
		"wrong-witness-name",
		"wrong-consent",
		"wrong-domain",
		"trailing-claims",
		"noncanonical-map",
	] {
		let (frame, boundary) = append(
			expected.coverage.boundary(),
			FrameKind::RemoteWitnessIntent,
			&vector(label),
		);
		let error = trust
			.from_witness_intent_frame(&frame, boundary, &expected)
			.unwrap_err();
		if label == "wrong-domain" {
			assert_eq!(error, Error::Owner(OwnerError::InvalidSignature));
		}
	}
	let (frame, boundary) = append(
		expected.coverage.boundary(),
		FrameKind::RemoteWitnessIntent,
		&[0; MAX_REMOTE_WITNESS_INTENT_BYTES + 1],
	);
	assert_eq!(
		trust.from_witness_intent_frame(&frame, boundary, &expected),
		Err(Error::Length)
	);
	let mut expected = expected;
	expected.consent.deadline = NonZeroU64::MIN;
	assert!(
		trust
			.sign_witness_intent(&expected, &run.fixture.key)
			.is_err()
	);
	expected.consent.deadline = NonZeroU64::MAX;
	expected.job_directory = expected.stage_directory;
	assert!(
		trust
			.sign_witness_intent(&expected, &run.fixture.key)
			.is_err()
	);
	expected.job_directory = LinuxFileIdentity::new(7, 11);
	assert_eq!(
		trust.sign_witness_intent(&expected, &SigningKey::from_bytes(&[0x63; 32])),
		Err(Error::Owner(OwnerError::UntrustedKey)),
	);
}

#[test]
fn receipt_ready_matches_canonical_artifact_and_exact_allocated_inode() {
	let run = Transcript::read(false);
	let expected = run.receipt();
	let payload = RemoteReceiptReady::encode(&expected).unwrap();
	assert_eq!(payload, vector("ready"));
	assert!(RemoteFinalizationRecord::decode(&payload).is_err());
	let (frame, end) = append(expected.boundary, FrameKind::RemoteReceiptReady, &payload);
	let verified = RemoteReceiptReady::from_frame(&frame, end, &expected).unwrap();
	assert_eq!(verified.boundary(), end);
	assert_eq!(verified.receipt(), expected.receipt);
	assert_eq!(verified.digest(), expected.digest);
	assert_eq!(verified.length(), expected.length);

	for label in [
		"wrong-receipt-name",
		"aliased-receipt",
		"legacy-ready",
		"zero-length-ready",
	] {
		let (frame, end) = append(
			expected.boundary,
			FrameKind::RemoteReceiptReady,
			&vector(label),
		);
		assert!(
			RemoteReceiptReady::from_frame(&frame, end, &expected).is_err(),
			"{label}"
		);
	}
	let (frame, end) = append(
		expected.boundary,
		FrameKind::RemoteReceiptReady,
		&[0xff; MAX_REMOTE_RECEIPT_READY_BYTES + 1],
	);
	assert_eq!(
		RemoteReceiptReady::from_frame(&frame, end, &expected),
		Err(Error::Length)
	);
	let shifted = RemoteReplayBoundary {
		offset: end.offset + 1,
		head: end.head,
	};
	assert_eq!(
		RemoteReceiptReady::from_frame(&frame, shifted, &expected),
		Err(Error::Length)
	);
}

#[test]
fn receipt_ready_refuses_wrong_history_chain_and_bounds() {
	let run = Transcript::read(false);
	let mut expected = run.receipt();
	let payload = RemoteReceiptReady::encode(&expected).unwrap();
	let (frame, end) = append(expected.boundary, FrameKind::RemoteReceiptReady, &payload);
	let shifted = RemoteReplayBoundary {
		offset: end.offset + 1,
		head: end.head,
	};
	assert_eq!(
		RemoteReceiptReady::from_frame(&frame, shifted, &expected),
		Err(Error::FrameBinding)
	);
	let (wrong, wrong_end) = append(expected.observed, FrameKind::RemoteReceiptReady, &payload);
	assert_eq!(
		RemoteReceiptReady::from_frame(&wrong, wrong_end, &expected),
		Err(Error::FrameBinding)
	);
	expected.receipt = expected.witness.job_directory();
	assert_eq!(RemoteReceiptReady::encode(&expected), Err(Error::Binding));
	expected.receipt = LinuxFileIdentity::new(8, 14);
	assert_eq!(RemoteReceiptReady::encode(&expected), Err(Error::Binding));
	expected.receipt = LinuxFileIdentity::new(7, 14);
	for length in [0, 6145] {
		expected.length = length;
		assert_eq!(RemoteReceiptReady::encode(&expected), Err(Error::Binding));
	}
	expected.length = 6144;
	assert!(RemoteReceiptReady::encode(&expected).is_ok());

	let mut expected = run.receipt();
	expected.metadata = ChainHead::after(expected.metadata.sequence(), [0x23; 32]).unwrap();
	assert_eq!(RemoteReceiptReady::encode(&expected), Err(Error::Binding));
	let mut expected = run.receipt();
	expected.durability = &run.frames[6].0;
	assert_eq!(
		RemoteReceiptReady::encode(&expected),
		Err(Error::FrameBinding)
	);
}

#[test]
fn neither_codec_accepts_any_truncated_payload_in_a_new_valid_frame() {
	let run = Transcript::read(false);
	let trust = run.fixture.trust();
	let replay = run.full_replay();
	let expected_intent = run.intent(&replay);
	let witness = run.frames[1].0.payload();
	for end in 0..witness.len() {
		let (frame, boundary) = append(
			expected_intent.coverage.boundary(),
			FrameKind::RemoteWitnessIntent,
			&witness[..end],
		);
		assert!(
			trust
				.from_witness_intent_frame(&frame, boundary, &expected_intent)
				.is_err(),
			"kind 41 cut {end}"
		);
	}
	let expected_receipt = run.receipt();
	let ready = vector("ready");
	for end in 0..ready.len() {
		let (frame, boundary) = append(
			expected_receipt.boundary,
			FrameKind::RemoteReceiptReady,
			&ready[..end],
		);
		assert!(
			RemoteReceiptReady::from_frame(&frame, boundary, &expected_receipt).is_err(),
			"kind 42 cut {end}"
		);
	}
}

#[path = "coverage_controls.rs"]
mod coverage_controls;
