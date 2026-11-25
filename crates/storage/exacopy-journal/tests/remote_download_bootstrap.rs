//! Signed stage bootstrap vectors and strict first-segment replay.

use std::io::Cursor;
use std::num::NonZeroU64;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{
	ChainHead, Frame, FrameKind, FrameProblem, FrameReadError, FrameReader, FrameWriter,
};
use exacopy_journal::remote_download::replay::{
	RemoteDownloadReplay, RemoteReplayBoundary, RemoteReplayIssue as Issue,
	RemoteReplayMismatch as Mismatch, RemoteReplayState as State, replay_remote_download,
	replay_remote_download_with_bootstrap,
};
use exacopy_journal::remote_download::{
	MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES, RemoteBootstrapTrust, RemoteDownloadBody as Body,
	RemoteDownloadContext, RemoteDownloadError as Error, RemoteDownloadOwnerRecord,
	RemoteDownloadRecord, RemoteEpochs, RemoteScopeDigest, RemoteSourceObservation,
	RemoteUncertainBoundary,
};
use exacopy_journal::{LinuxFileIdentity, OwnerError, OwnerProfileId, StreamDigest, StreamLength};

const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(7, 12);

struct Transcript {
	bytes: Vec<u8>,
	head: ChainHead,
}

impl Transcript {
	fn new() -> Self {
		Self {
			bytes: Vec::new(),
			head: ChainHead::start(),
		}
	}

	fn job(&mut self, owner: &RemoteDownloadOwnerRecord) -> Frame {
		let head = self.append(
			owner,
			Body::JobPrepared {
				scope: owner.manifest().scope.digest().unwrap(),
			},
		);
		self.frame(head)
	}

	fn frame(&self, target: ChainHead) -> Frame {
		let mut reader = FrameReader::new(self.bytes.as_slice(), ChainHead::start());
		loop {
			let frame = reader
				.next_frame()
				.unwrap()
				.expect("append supplies the frame");
			if frame.head() == target {
				return frame;
			}
		}
	}

	fn append(&mut self, owner: &RemoteDownloadOwnerRecord, body: Body<'_>) -> ChainHead {
		let manifest = owner.manifest();
		let context = RemoteDownloadContext {
			owner: owner.digest(),
			job: manifest.job,
			entry: manifest.scope.entry,
		};
		let payload = RemoteDownloadRecord::new(
			context,
			(self.head != ChainHead::start()).then_some(self.head),
			body,
		)
		.unwrap()
		.encode()
		.unwrap();
		self.append_raw(body.kind(), &payload)
	}

	fn append_raw(&mut self, kind: FrameKind, payload: &[u8]) -> ChainHead {
		let mut writer = FrameWriter::new(&mut self.bytes, self.head);
		self.head = writer.append(kind, payload).unwrap();
		self.head
	}

	fn boundary(&self) -> RemoteReplayBoundary {
		RemoteReplayBoundary {
			head: self.head,
			offset: self.bytes.len() as u64,
		}
	}

	fn replay(&self, trust: &RemoteBootstrapTrust<'_>) -> RemoteDownloadReplay {
		replay_remote_download_with_bootstrap(self.bytes.as_slice(), trust).unwrap()
	}
}

fn signer() -> SigningKey {
	SigningKey::from_bytes(&[0x52; 32])
}

fn profile() -> OwnerProfileId {
	OwnerProfileId::from_bytes([0x22; 16]).unwrap()
}

fn owner() -> RemoteDownloadOwnerRecord {
	RemoteDownloadOwnerRecord::decode(
		&decode_hex(include_str!("remote_download/owner.hex")),
		profile(),
		&signer().verifying_key(),
	)
	.unwrap()
}

fn decode_hex(input: &str) -> Vec<u8> {
	let ascii = input.split_ascii_whitespace().collect::<String>();
	let (pairs, remainder) = ascii.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty(), "fixture must contain complete octets");
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn epochs() -> RemoteEpochs {
	RemoteEpochs {
		run: NonZeroU64::new(1).unwrap(),
		source: NonZeroU64::new(21).unwrap(),
	}
}

fn allocation() -> Body<'static> {
	Body::StageAllocated {
		previous: None,
		next: epochs(),
		name: UnixComponent::new(b"attempt-1").unwrap(),
		nonce: [0x91; 16],
		source: RemoteSourceObservation::new(StreamLength::new(4).unwrap(), 0o100644, 67).unwrap(),
	}
}

fn entry_prepared(allocation: ChainHead, directory: LinuxFileIdentity) -> Body<'static> {
	Body::EntryPrepared {
		allocation,
		epochs: epochs(),
		nonce: [0x91; 16],
		stage_directory: directory,
		stage: LinuxFileIdentity::new(7, 13),
	}
}

fn vector(label: &str) -> Vec<u8> {
	include_str!("remote_download/bootstrap.hex")
		.lines()
		.find_map(|line| {
			let (name, bytes) = line.split_once(' ')?;
			(name == label).then(|| decode_hex(bytes))
		})
		.expect("named independent fixture")
}

fn assert_mismatch(history: &RemoteDownloadReplay, expected: Mismatch) {
	assert!(
		matches!(
			history.state(),
			State::ReconciliationRequired(Issue::Record { problem, .. }) if *problem == expected
		),
		"wrong refusal for {:?}: {:?}",
		history.boundary(),
		history.state()
	);
}

#[test]
fn independent_signed_bootstrap_binds_the_exact_first_job_frame() {
	let owner = owner();
	let signer = signer();
	let key = signer.verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut transcript = Transcript::new();
	let job = transcript.job(&owner);
	let payload = vector("valid");
	assert_eq!(trust.sign(&job, STAGE, &signer).unwrap(), payload);
	assert!(matches!(
		RemoteDownloadRecord::decode(&payload),
		Err(Error::Shape)
	));

	let bootstrap = transcript.append_raw(FrameKind::StageDirectoryPrepared, &payload);
	let frame = transcript.frame(bootstrap);
	assert_eq!(frame.kind().code(), 38);
	let accepted = trust.from_frame(&frame, &job).unwrap();
	assert_eq!(accepted.head(), bootstrap);
	assert_eq!(accepted.directory(), STAGE);
	let replay = transcript.replay(&trust);
	assert_eq!(replay.job_prepared(), Some(job.head()));
	assert_eq!(replay.stage_directory_prepared(), Some(accepted));
	assert!(matches!(replay.state(), State::StageDirectoryPrepared));
	assert!(replay.attempts().is_empty());

	let legacy = replay_remote_download(transcript.bytes.as_slice(), &owner).unwrap();
	assert_eq!(legacy.boundary().head, job.head());
	assert_mismatch(&legacy, Mismatch::UnsupportedKind);
}

#[test]
fn independently_signed_substitutions_never_become_bootstrap_authority() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	for (label, error) in [
		("new-version", Error::UnsupportedVersion),
		("foreign-domain", Error::Owner(OwnerError::WrongDomain)),
		("wrong-prefix", Error::Owner(OwnerError::InvalidSignature)),
		("other-key", Error::Owner(OwnerError::InvalidSignature)),
		(
			"changed-signature",
			Error::Owner(OwnerError::InvalidSignature),
		),
		("other-owner", Error::Binding),
		("other-job", Error::Binding),
		("other-entry", Error::Binding),
		("other-profile", Error::Binding),
		("other-predecessor", Error::FrameBinding),
		("other-sequence", Error::FrameBinding),
		("foreign-device", Error::Binding),
		("aliased-job", Error::Binding),
		("aliased-destination", Error::Binding),
		("other-role", Error::Binding),
		("duplicate-field", Error::Shape),
		("noncanonical-body", Error::NonCanonical),
		("noncanonical-envelope", Error::NonCanonical),
		("trailing-byte", Error::NonCanonical),
	] {
		let mut transcript = Transcript::new();
		let job = transcript.job(&owner);
		let accepted = transcript.boundary();
		let alleged = transcript.append_raw(FrameKind::StageDirectoryPrepared, &vector(label));
		assert_eq!(
			trust.from_frame(&transcript.frame(alleged), &job),
			Err(error),
			"{label}"
		);
		let history = transcript.replay(&trust);
		assert_mismatch(&history, Mismatch::Payload(error));
		assert_eq!(history.boundary(), accepted, "{label}");
		assert_eq!(history.stage_directory_prepared(), None, "{label}");
		assert!(history.attempts().is_empty(), "{label}");
	}
}

#[test]
fn signing_and_decode_require_independent_owner_key_and_actual_first_record() {
	let owner = owner();
	let signer = signer();
	let key = signer.verifying_key();
	let other = SigningKey::from_bytes(&[0x53; 32]);
	let other_profile = OwnerProfileId::from_bytes([0x54; 16]).unwrap();
	assert!(matches!(
		RemoteBootstrapTrust::new(&owner, other_profile, &key),
		Err(Error::Owner(OwnerError::UntrustedProfile))
	));
	assert!(matches!(
		RemoteBootstrapTrust::new(&owner, profile(), &other.verifying_key()),
		Err(Error::Owner(OwnerError::UntrustedKey))
	));
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut transcript = Transcript::new();
	let job = transcript.job(&owner);
	assert_eq!(
		trust.sign(&job, STAGE, &other),
		Err(Error::Owner(OwnerError::UntrustedKey))
	);
	assert_eq!(
		trust.sign(&job, owner.manifest().job_directory, &signer),
		Err(Error::Binding)
	);
	let job_scope = RemoteScopeDigest::from_bytes([0xa7; 32]);
	let mut foreign = Transcript::new();
	let wrong = foreign.append(&owner, Body::JobPrepared { scope: job_scope });
	let wrong = foreign.frame(wrong);
	assert_eq!(trust.sign(&wrong, STAGE, &signer), Err(Error::Binding));
	let boot = transcript.append_raw(FrameKind::StageDirectoryPrepared, &vector("valid"));
	let boot = transcript.frame(boot);
	assert_eq!(trust.from_frame(&boot, &wrong), Err(Error::Binding));
	let allocated = transcript.append(&owner, allocation());
	let allocated = transcript.frame(allocated);
	assert_eq!(trust.sign(&allocated, STAGE, &signer), Err(Error::Binding));
	assert_eq!(trust.from_frame(&allocated, &job), Err(Error::FrameBinding));
}

#[test]
fn oversized_strict_bootstrap_stops_before_consuming_any_payload_bytes() {
	const FRAME_HEADER_BYTES: u64 = 56;
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut oversized = Transcript::new();
	let job = oversized.job(&owner);
	let accepted = oversized.boundary();
	let excess = oversized.append_raw(
		FrameKind::StageDirectoryPrepared,
		&[0; MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES + 1],
	);
	let frame = oversized.frame(excess);
	assert_eq!(trust.from_frame(&frame, &job), Err(Error::Length));

	let mut input = Cursor::new(oversized.bytes.as_slice());
	let replay = replay_remote_download_with_bootstrap(&mut input, &trust).unwrap();
	assert_eq!(input.position(), accepted.offset + FRAME_HEADER_BYTES);
	assert_eq!(replay.boundary(), accepted);
	assert!(matches!(
		replay.state(),
		State::ReconciliationRequired(Issue::Framing(FrameReadError::Corrupt {
			offset,
			problem: FrameProblem::PayloadTooLarge(declared),
		})) if *offset == accepted.offset
			&& usize::try_from(*declared).unwrap() == MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES + 1
	));
}

#[test]
fn strict_profile_refuses_missing_first_repeated_and_late_bootstrap() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let payload = vector("valid");

	let mut first = Transcript::new();
	let empty = first.boundary();
	first.append_raw(FrameKind::StageDirectoryPrepared, &payload);
	let refused = first.replay(&trust);
	assert_eq!(refused.boundary(), empty);
	assert_mismatch(&refused, Mismatch::Order);

	let mut late = Transcript::new();
	late.job(&owner);
	let prepared = late.boundary();
	let allocation = late.append(&owner, allocation());
	let legacy = replay_remote_download(late.bytes.as_slice(), &owner).unwrap();
	assert_eq!(legacy.attempts()[0].allocation(), allocation);
	late.append_raw(FrameKind::StageDirectoryPrepared, &payload);
	let refused = late.replay(&trust);
	assert_eq!(refused.boundary(), prepared);
	assert_mismatch(&refused, Mismatch::BootstrapRequired);
	assert!(refused.attempts().is_empty());

	let mut duplicate = Transcript::new();
	duplicate.job(&owner);
	duplicate.append_raw(FrameKind::StageDirectoryPrepared, &payload);
	let accepted = duplicate.boundary();
	duplicate.append_raw(FrameKind::StageDirectoryPrepared, &payload);
	let refused = duplicate.replay(&trust);
	assert_eq!(refused.boundary(), accepted);
	assert_eq!(
		refused.stage_directory_prepared().unwrap().head(),
		accepted.head
	);
	assert_mismatch(&refused, Mismatch::Order);
}

#[test]
fn first_entry_prepared_must_bind_the_signed_directory() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut transcript = Transcript::new();
	transcript.job(&owner);
	transcript.append_raw(FrameKind::StageDirectoryPrepared, &vector("valid"));
	let allocation = transcript.append(&owner, allocation());
	let accepted = transcript.boundary();
	transcript.append(
		&owner,
		entry_prepared(allocation, LinuxFileIdentity::new(7, 14)),
	);
	let refused = transcript.replay(&trust);
	assert_eq!(refused.boundary(), accepted);
	assert_eq!(
		refused.stage_directory_prepared().unwrap().directory(),
		STAGE
	);
	assert_eq!(refused.attempts()[0].prepared(), None);
	assert_mismatch(&refused, Mismatch::StageBinding);
}

#[test]
fn strict_transcript_keeps_only_complete_authenticated_boundaries_at_every_cut() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut transcript = Transcript::new();
	let empty = transcript.boundary();
	transcript.job(&owner);
	let job = transcript.boundary();
	transcript.append_raw(FrameKind::StageDirectoryPrepared, &vector("valid"));
	let bootstrap = transcript.boundary();
	let allocation = transcript.append(&owner, allocation());
	let allocated = transcript.boundary();
	let binding = transcript.append(&owner, entry_prepared(allocation, STAGE));
	let bound = transcript.boundary();
	transcript.append(
		&owner,
		Body::RangeCheckpoint {
			prepared: binding,
			epochs: epochs(),
			ordinal: 1,
			offset: 0,
			length: 4,
			digest: StreamDigest::from_bytes([0x55; 32]),
		},
	);
	let covered = transcript.boundary();
	transcript.append(
		&owner,
		Body::FailureRecorded {
			attempt: binding,
			epochs: epochs(),
			boundary: RemoteUncertainBoundary::TerminalSource,
		},
	);
	let uncertain = transcript.boundary();
	let boundaries = [empty, job, bootstrap, allocated, bound, covered, uncertain];

	for cut in 0..=transcript.bytes.len() {
		let scan = replay_remote_download_with_bootstrap(&transcript.bytes[..cut], &trust).unwrap();
		let cut = cut as u64;
		let expected = *boundaries
			.iter()
			.rev()
			.find(|edge| edge.offset <= cut)
			.unwrap();
		assert_eq!(scan.boundary(), expected, "cut at {cut}");
		assert_eq!(
			scan.stage_directory_prepared().map(|proof| proof.head()),
			(cut >= bootstrap.offset).then_some(bootstrap.head),
			"cut at {cut}"
		);
		assert_eq!(scan.attempts().len(), usize::from(cut >= allocated.offset));
		assert_eq!(
			scan.recorded_uncertainty().is_some(),
			cut >= uncertain.offset
		);
		if cut > expected.offset {
			assert!(
				matches!(scan.state(), State::ReconciliationRequired(Issue::Framing(
					FrameReadError::TornTail { offset, bytes_read })
				) if *offset == expected.offset && *bytes_read as u64 == cut - *offset),
				"cut at {cut}: {:?}",
				scan.state()
			);
			continue;
		}
		assert!(
			match scan.state() {
				State::ReconciliationRequired(Issue::StageBootstrapMissing) =>
					expected == empty || expected == job,
				State::StageDirectoryPrepared => expected == bootstrap,
				State::AllocationUnbound => expected == allocated,
				State::StageBound => expected == bound || expected == covered,
				State::ReconciliationRequired(Issue::RecordedUncertainty) => expected == uncertain,
				_ => false,
			},
			"cut at {cut}: {:?}",
			scan.state()
		);
	}
}
