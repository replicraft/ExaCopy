//! Independent canonical kind-40 transcript and refusal controls.

use std::num::NonZeroU64;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind, FrameReader, FrameWriter,
};
use exacopy_journal::remote_download::continuation::{
	CoverageBasis, MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES, PriorPreparation,
	RemoteContinuationClaims, RemoteContinuationCoverage, RemoteContinuationExpectation,
	RemoteContinuationPrior,
};
use exacopy_journal::remote_download::finalization::RemoteFinalizationRecord;
use exacopy_journal::remote_download::finalization_replay::{
	replay_remote_finalization, replay_remote_finalization_with_checkpoints,
};
use exacopy_journal::remote_download::replay::{
	RemoteReplayBoundary, RemoteReplayState, replay_remote_download_with_bootstrap,
};
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadError as Error, RemoteDownloadOwnerRecord,
	RemoteDownloadRecord, RemoteEpochs, RemoteSourceObservation,
};
use exacopy_journal::{LinuxFileIdentity, OwnerError, OwnerProfileId, StreamDigest, StreamLength};

const STAGE_NAME: [u8; 255] = {
	let mut bytes = [b's'; 255];
	bytes[254] = 0xff;
	bytes
};
const QUALIFICATION: [u8; 32] = [0x71; 32];

fn hex(text: &str) -> Vec<u8> {
	let text = text.split_ascii_whitespace().collect::<String>();
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn profile() -> OwnerProfileId {
	OwnerProfileId::from_bytes([0x22; 16]).unwrap()
}

fn length(bytes: u64) -> StreamLength {
	StreamLength::new(bytes).unwrap()
}

struct Fixture {
	owner: RemoteDownloadOwnerRecord,
	key: SigningKey,
	verify: VerifyingKey,
	journal: Vec<u8>,
	prefix_end: usize,
	preceding: RemoteReplayBoundary,
	final_frame: Frame,
	end: RemoteReplayBoundary,
}

impl Fixture {
	fn read() -> Self {
		let key = SigningKey::from_bytes(&[0x52; 32]);
		let verify = key.verifying_key();
		let owner = RemoteDownloadOwnerRecord::decode(
			&hex(include_str!("remote_finalization/owner.hex")),
			profile(),
			&verify,
		)
		.unwrap();
		let journal = hex(include_str!("remote_continuation/journal.hex"));
		let mut reader = FrameReader::new(journal.as_slice(), ChainHead::start());
		for kind in [
			FrameKind::JobPrepared,
			FrameKind::StageDirectoryPrepared,
			FrameKind::RemoteStageAllocated,
			FrameKind::EntryPrepared,
			FrameKind::RangeCheckpoint,
		] {
			assert_eq!(reader.next_frame().unwrap().unwrap().kind(), kind);
		}
		let preceding = RemoteReplayBoundary {
			head: reader.head(),
			offset: reader.offset(),
		};
		let prefix_end = usize::try_from(reader.offset()).unwrap();
		let final_frame = reader.next_frame().unwrap().unwrap();
		let end = RemoteReplayBoundary {
			head: reader.head(),
			offset: reader.offset(),
		};
		assert!(reader.next_frame().unwrap().is_none());
		Self {
			owner,
			key,
			verify,
			journal,
			prefix_end,
			preceding,
			final_frame,
			end,
		}
	}

	fn trust(&self) -> RemoteBootstrapTrust<'_> {
		RemoteBootstrapTrust::new(&self.owner, profile(), &self.verify).unwrap()
	}

	fn expectation(&self) -> RemoteContinuationExpectation<'_> {
		let trust = self.trust();
		let replay = replay_remote_finalization_with_checkpoints(
			&self.journal[..self.prefix_end],
			&trust,
			QUALIFICATION,
			None,
		)
		.unwrap();
		let inventory = replay.active_checkpoints().unwrap();
		let checkpoints = inventory.checkpoints();
		assert_eq!(checkpoints.len(), 1);
		let prepared = inventory.prepared();
		let row = checkpoints[0];
		assert_eq!(inventory.name(), STAGE_NAME);
		RemoteContinuationExpectation {
			claims: RemoteContinuationClaims {
				context: inventory.context(),
				scope: inventory.scope().unwrap(),
				previous: inventory.boundary(),
				prior: RemoteContinuationPrior {
					bootstrap: replay.stage_directory_prepared().unwrap().head(),
					allocation: inventory.allocation(),
					prepared: prepared.head,
					active: PriorPreparation::Original(prepared.head),
					epochs: inventory.epochs(),
					name: UnixComponent::new(&STAGE_NAME).unwrap(),
					nonce: *inventory.nonce(),
				},
				directory: prepared.directory,
				stage: prepared.file,
				coverage: RemoteContinuationCoverage {
					basis: CoverageBasis::Checkpoint {
						head: row.head(),
						ordinal: row.ordinal(),
					},
					end: length(inventory.covered_extent()),
				},
				epochs: RemoteEpochs {
					run: NonZeroU64::new(2).unwrap(),
					source: NonZeroU64::new(9).unwrap(),
				},
				source: RemoteSourceObservation::new(length(5), 0o100600, 23).unwrap(),
				adopted_end: length(4),
				prefix_digest: StreamDigest::from_bytes(*blake3::hash(b"ABCD").as_bytes()),
				grant_digest: [0x72; 32],
				qualification_digest: QUALIFICATION,
			},
			prior_source_extent: inventory.source().length(),
		}
	}

	fn frame(&self, kind: FrameKind, payload: &[u8]) -> (Frame, RemoteReplayBoundary) {
		let mut writer = FrameWriter::new(Vec::new(), self.preceding.head);
		writer.append(kind, payload).unwrap();
		let bytes = writer.into_inner();
		let mut reader = FrameReader::new(bytes.as_slice(), self.preceding.head);
		let frame = reader.next_frame().unwrap().unwrap();
		let boundary = RemoteReplayBoundary {
			head: frame.head(),
			offset: self.preceding.offset + reader.offset(),
		};
		(frame, boundary)
	}
}

#[test]
fn independent_transcript_authenticates_and_reencodes_byte_exactly() {
	let fixture = Fixture::read();
	let expected = fixture.expectation();
	let trust = fixture.trust();
	let payload = trust.sign_continuation(&expected, &fixture.key).unwrap();
	assert_eq!(payload, fixture.final_frame.payload());
	assert!(payload.len() <= MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES);
	let decoded = trust
		.from_continuation_frame(&fixture.final_frame, fixture.end, &expected)
		.unwrap();
	assert_eq!(decoded.boundary(), fixture.end);
	assert_eq!(decoded.claims(), expected.claims);
	assert_eq!(decoded.claims().prior.name.as_bytes()[254], 0xff);
}

#[test]
fn independently_signed_malformed_and_foreign_payloads_refuse() {
	let fixture = Fixture::read();
	let expected = fixture.expectation();
	let trust = fixture.trust();
	for (hex_payload, error) in [
		(
			include_str!("remote_continuation/future_features.hex"),
			Error::UnsupportedVersion,
		),
		(
			include_str!("remote_continuation/future_version.hex"),
			Error::UnsupportedVersion,
		),
		(
			include_str!("remote_continuation/wrong_domain.hex"),
			Error::Owner(OwnerError::InvalidSignature),
		),
		(
			include_str!("remote_continuation/other_key.hex"),
			Error::Owner(OwnerError::InvalidSignature),
		),
		(
			include_str!("remote_continuation/noncanonical_body.hex"),
			Error::NonCanonical,
		),
		(
			include_str!("remote_continuation/foreign_stage.hex"),
			Error::Binding,
		),
		(
			include_str!("remote_continuation/body_trailing.hex"),
			Error::NonCanonical,
		),
	] {
		let (frame, end) = fixture.frame(FrameKind::RemoteCaptureContinued, &hex(hex_payload));
		assert_eq!(
			trust.from_continuation_frame(&frame, end, &expected),
			Err(error)
		);
	}
}

#[test]
fn invalid_continuation_body_refuses_before_an_invalid_signature() {
	let fixture = Fixture::read();
	let expected = fixture.expectation();
	let trust = fixture.trust();
	for (hex_payload, error) in [
		(
			include_str!("remote_continuation/noncanonical_body.hex"),
			Error::NonCanonical,
		),
		(
			include_str!("remote_continuation/future_features.hex"),
			Error::UnsupportedVersion,
		),
	] {
		let mut payload = hex(hex_payload);
		*payload.last_mut().unwrap() ^= 1; // The final envelope field is the signature.
		let (frame, end) = fixture.frame(FrameKind::RemoteCaptureContinued, &payload);
		assert_eq!(
			trust.from_continuation_frame(&frame, end, &expected),
			Err(error)
		);
	}
}

#[test]
fn all_cuts_and_excess_payload_refuse() {
	let fixture = Fixture::read();
	let expected = fixture.expectation();
	let trust = fixture.trust();
	let payload = fixture.final_frame.payload();
	for cut in 0..payload.len() {
		let (frame, end) = fixture.frame(FrameKind::RemoteCaptureContinued, &payload[..cut]);
		assert!(
			trust
				.from_continuation_frame(&frame, end, &expected)
				.is_err(),
			"cut {cut}"
		);
	}
	let mut trailing = payload.to_vec();
	trailing.push(0);
	let (frame, end) = fixture.frame(FrameKind::RemoteCaptureContinued, &trailing);
	assert_eq!(
		trust.from_continuation_frame(&frame, end, &expected),
		Err(Error::NonCanonical)
	);
	let overflow = [0; MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES + 1];
	let (frame, end) = fixture.frame(FrameKind::RemoteCaptureContinued, &overflow);
	assert_eq!(
		trust.from_continuation_frame(&frame, end, &expected),
		Err(Error::Length)
	);
}

#[test]
fn boundaries_and_exact_expected_native_and_grant_context_refuse_substitution() {
	let fixture = Fixture::read();
	let expected = fixture.expectation();
	let trust = fixture.trust();
	let mut wrong_end = fixture.end;
	wrong_end.offset += 1;
	assert_eq!(
		trust.from_continuation_frame(&fixture.final_frame, wrong_end, &expected),
		Err(Error::FrameBinding),
	);
	let (frame, end) = fixture.frame(FrameKind::EntryPrepared, fixture.final_frame.payload());
	assert_eq!(
		trust.from_continuation_frame(&frame, end, &expected),
		Err(Error::FrameBinding)
	);
	for claims in [
		RemoteContinuationClaims {
			grant_digest: [7; 32],
			..expected.claims
		},
		RemoteContinuationClaims {
			qualification_digest: [8; 32],
			..expected.claims
		},
		RemoteContinuationClaims {
			stage: LinuxFileIdentity::new(7, 14),
			..expected.claims
		},
	] {
		assert_eq!(
			trust.from_continuation_frame(
				&fixture.final_frame,
				fixture.end,
				&RemoteContinuationExpectation { claims, ..expected }
			),
			Err(Error::Binding),
		);
	}
	let wrong_prior = RemoteContinuationExpectation {
		prior_source_extent: length(3),
		..expected
	};
	assert_eq!(
		trust.sign_continuation(&wrong_prior, &fixture.key),
		Err(Error::Binding)
	);
	assert_eq!(
		trust.from_continuation_frame(&fixture.final_frame, fixture.end, &wrong_prior),
		Err(Error::Binding),
	);
}

#[test]
fn independently_selected_owner_key_and_profile_are_required() {
	let fixture = Fixture::read();
	let other = SigningKey::from_bytes(&[0x53; 32]);
	assert!(RemoteBootstrapTrust::new(&fixture.owner, profile(), &other.verifying_key()).is_err());
	let other_profile = OwnerProfileId::from_bytes([0x25; 16]).unwrap();
	assert!(RemoteBootstrapTrust::new(&fixture.owner, other_profile, &fixture.verify).is_err());
	let mut identity = [0; 32];
	identity[0] = 1;
	let weak = VerifyingKey::from_bytes(&identity).unwrap();
	assert!(weak.is_weak());
	assert!(RemoteBootstrapTrust::new(&fixture.owner, profile(), &weak).is_err());
	assert_eq!(
		fixture
			.trust()
			.sign_continuation(&fixture.expectation(), &other),
		Err(Error::Owner(OwnerError::UntrustedKey)),
	);
}

#[test]
fn legacy_record_apis_refuse_continuation_at_the_exact_prior_boundary() {
	let fixture = Fixture::read();
	let trust = fixture.trust();
	let trace = fixture.journal.as_slice();
	let capture = replay_remote_download_with_bootstrap(trace, &trust).unwrap();
	let full = replay_remote_finalization(trace, &trust, QUALIFICATION, None).unwrap();
	assert_eq!(capture.boundary(), fixture.preceding);
	assert!(matches!(
		capture.state(),
		RemoteReplayState::ReconciliationRequired(_)
	));
	assert_eq!(full.boundary(), fixture.preceding);
	assert!(full.issue().is_some());
	assert!(RemoteDownloadRecord::from_frame(&fixture.final_frame).is_err());
	assert!(RemoteFinalizationRecord::from_frame(&fixture.final_frame).is_err());
	assert_eq!(
		fixture.end.offset - fixture.preceding.offset,
		u64::try_from(FRAME_OVERHEAD_BYTES + fixture.final_frame.payload().len()).unwrap(),
	);
}

#[test]
fn signer_refuses_impossible_structural_claims_and_accepts_zero_tail() {
	let fixture = Fixture::read();
	let expected = fixture.expectation();
	let trust = fixture.trust();
	let mut changed = expected;
	changed.claims.source = RemoteSourceObservation::new(length(4), 0o100600, 23).unwrap();
	assert!(trust.sign_continuation(&changed, &fixture.key).is_ok());
	for claims in [
		RemoteContinuationClaims {
			epochs: expected.claims.prior.epochs,
			..expected.claims
		},
		RemoteContinuationClaims {
			adopted_end: length(1),
			..expected.claims
		},
		RemoteContinuationClaims {
			previous: RemoteReplayBoundary {
				offset: exacopy_journal::MAX_FIRST_SEGMENT_BYTES - 1,
				..expected.claims.previous
			},
			..expected.claims
		},
		RemoteContinuationClaims {
			coverage: RemoteContinuationCoverage {
				basis: CoverageBasis::ContinuedPrefix(expected.claims.previous.head),
				..expected.claims.coverage
			},
			..expected.claims
		},
	] {
		assert!(
			trust
				.sign_continuation(
					&RemoteContinuationExpectation { claims, ..expected },
					&fixture.key
				)
				.is_err()
		);
	}
}

#[path = "remote_continuation/witness_closeout.rs"]
mod witness_closeout;
