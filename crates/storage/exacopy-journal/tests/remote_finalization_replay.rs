//! One-stream replay controls across the authenticated bootstrap and finalization profiles.

use std::num::NonZeroU64;

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::remote_download::finalization::{
	RemoteFinalizationBinding, RemoteFinalizationBody as Final, RemoteFinalizationRecord,
	RemoteLocalMetadata, RemotePublicationObservation, RemotePublishTarget, RemoteReceiptDigest,
};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase as Phase, RemoteReceiptAssociation as Association,
	replay_remote_finalization,
};
use exacopy_journal::remote_download::replay::{RemoteReplayIssue, RemoteReplayMismatch};
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadBody as Capture, RemoteDownloadContext,
	RemoteDownloadOwnerRecord, RemoteDownloadRecord, RemoteEpochs, RemoteSourceObservation,
};
use exacopy_journal::{LinuxFileIdentity, OwnerProfileId, StreamDigest, StreamLength};

const QUALIFICATION: [u8; 32] = [0x71; 32];
const DIRECTORY: LinuxFileIdentity = LinuxFileIdentity::new(7, 12);
const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(7, 13);

struct Journal {
	bytes: Vec<u8>,
	head: ChainHead,
	context: RemoteDownloadContext,
	epochs: RemoteEpochs,
	prepared: ChainHead,
}

impl Journal {
	fn start(owner: &RemoteDownloadOwnerRecord) -> Self {
		Self {
			bytes: Vec::new(),
			head: ChainHead::start(),
			context: RemoteDownloadContext {
				owner: owner.digest(),
				job: owner.manifest().job,
				entry: owner.manifest().scope.entry,
			},
			epochs: RemoteEpochs {
				run: NonZeroU64::new(1).unwrap(),
				source: NonZeroU64::new(7).unwrap(),
			},
			prepared: ChainHead::start(),
		}
	}

	fn raw(&mut self, kind: FrameKind, payload: &[u8]) -> ChainHead {
		let mut writer = FrameWriter::new(&mut self.bytes, self.head);
		self.head = writer.append(kind, payload).unwrap();
		self.head
	}

	fn capture(&mut self, body: Capture<'_>) -> ChainHead {
		let prior = (self.head != ChainHead::start()).then_some(self.head);
		let record = RemoteDownloadRecord::new(self.context, prior, body).unwrap();
		self.raw(body.kind(), &record.encode().unwrap())
	}

	fn prepare(&mut self, trust: &RemoteBootstrapTrust<'_>, owner: &RemoteDownloadOwnerRecord) {
		self.capture(Capture::JobPrepared {
			scope: owner.manifest().scope.digest().unwrap(),
		});
		let job = FrameReader::new(self.bytes.as_slice(), ChainHead::start())
			.next_frame()
			.unwrap()
			.unwrap();
		let bootstrap = trust.sign(&job, DIRECTORY, &signer()).unwrap();
		self.raw(FrameKind::StageDirectoryPrepared, &bootstrap);
		let nonce = [0x61; 16];
		let allocation = self.capture(Capture::StageAllocated {
			previous: None,
			next: self.epochs,
			name: UnixComponent::new(b"attempt").unwrap(),
			nonce,
			source: RemoteSourceObservation::new(length(), 0o100644, 22).unwrap(),
		});
		self.prepared = self.capture(Capture::EntryPrepared {
			allocation,
			epochs: self.epochs,
			nonce,
			stage_directory: DIRECTORY,
			stage: STAGE,
		});
	}

	fn checkpoint(&mut self, ordinal: u16, offset: u64) {
		self.capture(Capture::RangeCheckpoint {
			prepared: self.prepared,
			epochs: self.epochs,
			ordinal,
			offset,
			length: 2,
			digest: StreamDigest::from_bytes([0x42; 32]),
		});
	}

	fn final_record(&mut self, body: Final<'_>) -> ChainHead {
		let binding = RemoteFinalizationBinding {
			context: self.context,
			prepared: self.prepared,
			epochs: self.epochs,
			stage: STAGE,
		};
		let record = RemoteFinalizationRecord::new(binding, self.head, body).unwrap();
		self.raw(body.kind(), &record.encode().unwrap())
	}

	fn intent(&mut self, owner: &RemoteDownloadOwnerRecord) -> ChainHead {
		let seal = self.final_record(Final::StageSealed {
			directory: DIRECTORY,
			length: length(),
		});
		let digest = StreamDigest::from_bytes([0x13; 32]);
		let verification = self.final_record(Final::VerificationRecorded {
			length: length(),
			source: digest,
			stage: digest,
		});
		let metadata = self.final_record(Final::MetadataRecorded(RemoteLocalMetadata {
			uid: 1000,
			gid: 1001,
		}));
		let destination = &owner.manifest().scope.destination;
		self.final_record(Final::PublishIntent {
			seal,
			verification,
			directory: DIRECTORY,
			target: RemotePublishTarget {
				root: destination.root(),
				parent: destination.parent(),
				component: UnixComponent::new(destination.target()).unwrap(),
			},
			qualification: QUALIFICATION,
		});
		metadata
	}
}

fn length() -> StreamLength {
	StreamLength::new(11).unwrap()
}

fn signer() -> SigningKey {
	SigningKey::from_bytes(&[0x52; 32])
}

fn profile() -> OwnerProfileId {
	OwnerProfileId::from_bytes([0x22; 16]).unwrap()
}

fn owner() -> RemoteDownloadOwnerRecord {
	let text = include_str!("remote_finalization/owner.hex")
		.split_ascii_whitespace()
		.collect::<String>();
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	assert!(
		remainder.is_empty(),
		"owner fixture must contain complete octets"
	);
	let bytes = pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect::<Vec<_>>();
	RemoteDownloadOwnerRecord::decode(&bytes, profile(), &signer().verifying_key()).unwrap()
}

#[test]
fn only_clear_exact_commit_associates_receipt_after_accepted_checkpoint() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	journal.checkpoint(1, 0);
	let metadata = journal.intent(&owner);
	journal.final_record(Final::PublishObserved(
		RemotePublicationObservation::Published(STAGE),
	));
	journal.final_record(Final::DurabilityRecorded {
		metadata,
		directory: DIRECTORY,
		parent: owner.manifest().scope.destination.parent(),
		qualification: QUALIFICATION,
	});
	let durable =
		replay_remote_finalization(journal.bytes.as_slice(), &trust, QUALIFICATION, None).unwrap();
	assert_eq!(durable.phase(), Phase::Durable);
	assert_eq!(durable.attempts()[0].covered_extent(), 2);
	assert!(durable.validated_receipt().unwrap().is_none());
	let candidate = durable.receipt_candidate().unwrap().unwrap();
	let bytes = candidate.encode().unwrap();

	let durable_bytes = journal.bytes.len();
	let durable_head = journal.head;
	journal.final_record(Final::ReceiptCommitted {
		digest: RemoteReceiptDigest::from_bytes([0x44; 32]),
	});
	let forged = replay_remote_finalization(
		journal.bytes.as_slice(),
		&trust,
		QUALIFICATION,
		Some(&bytes),
	)
	.unwrap();
	assert_eq!(forged.boundary().head, durable_head);
	assert_eq!(forged.phase(), Phase::Durable);
	assert!(forged.issue().is_some());
	assert!(forged.validated_receipt().unwrap().is_none());

	journal.bytes.truncate(durable_bytes);
	journal.head = durable_head;
	journal.final_record(Final::ReceiptCommitted {
		digest: candidate.digest().unwrap(),
	});

	let inspect = |artifact| {
		replay_remote_finalization(journal.bytes.as_slice(), &trust, QUALIFICATION, artifact)
			.unwrap()
	};
	let matched = inspect(Some(&bytes));
	assert_eq!(matched.phase(), Phase::ReceiptCommitted);
	assert_eq!(matched.receipt_association(), Association::Matched);
	assert_eq!(
		matched
			.validated_receipt()
			.unwrap()
			.unwrap()
			.encode()
			.unwrap(),
		bytes
	);
	assert_eq!(inspect(None).receipt_association(), Association::Missing);
	assert!(matches!(
		inspect(Some(&bytes[..bytes.len() - 1])).receipt_association(),
		Association::Refused(_)
	));

	journal.bytes.extend_from_slice(b"EXA");
	let torn = replay_remote_finalization(
		journal.bytes.as_slice(),
		&trust,
		QUALIFICATION,
		Some(&bytes),
	)
	.unwrap();
	assert_eq!(torn.boundary().head, journal.head);
	assert_eq!(torn.receipt_association(), Association::UnclearEnd);
	assert!(torn.validated_receipt().unwrap().is_none());
	assert!(matches!(torn.issue(), Some(RemoteReplayIssue::Framing(_))));
}

#[test]
fn invalid_checkpoint_retains_preparation_and_never_accepts_seal() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	journal.checkpoint(2, 2);
	journal.final_record(Final::StageSealed {
		directory: DIRECTORY,
		length: length(),
	});
	let replay =
		replay_remote_finalization(journal.bytes.as_slice(), &trust, QUALIFICATION, None).unwrap();
	assert_eq!(replay.phase(), Phase::Capture);
	assert_eq!(replay.boundary().head, journal.prepared);
	assert!(matches!(
		replay.issue(),
		Some(RemoteReplayIssue::Record {
			problem: RemoteReplayMismatch::Checkpoint,
			..
		})
	));
}

#[test]
fn qualified_intent_and_recorded_conflict_never_imply_a_receipt() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	journal.intent(&owner);

	let wrong =
		replay_remote_finalization(journal.bytes.as_slice(), &trust, [0x72; 32], None).unwrap();
	assert_eq!(wrong.phase(), Phase::MetadataReady);
	assert!(matches!(
		wrong.issue(),
		Some(RemoteReplayIssue::Record {
			problem: RemoteReplayMismatch::Scope,
			..
		})
	));

	let conflict = journal.final_record(Final::PublishObserved(
		RemotePublicationObservation::Conflict,
	));
	journal.final_record(Final::ReceiptCommitted {
		digest: RemoteReceiptDigest::from_bytes([0x44; 32]),
	});
	let replay =
		replay_remote_finalization(journal.bytes.as_slice(), &trust, QUALIFICATION, None).unwrap();
	assert_eq!(replay.phase(), Phase::Conflict);
	assert_eq!(replay.boundary().head, conflict);
	assert!(replay.receipt_candidate().unwrap().is_none());
}

#[test]
fn sealed_preintent_prefix_survives_a_new_allocation_without_restart_record() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	let seal = journal.final_record(Final::StageSealed {
		directory: DIRECTORY,
		length: length(),
	});
	let inspected =
		replay_remote_finalization(journal.bytes.as_slice(), &trust, QUALIFICATION, None).unwrap();
	assert_eq!(inspected.phase(), Phase::Sealed);
	assert_eq!(inspected.seal(), Some(seal));
	assert!(inspected.issue().is_none());
	let next = RemoteEpochs {
		run: NonZeroU64::new(2).unwrap(),
		source: NonZeroU64::new(8).unwrap(),
	};
	journal.capture(Capture::StageAllocated {
		previous: Some(journal.epochs),
		next,
		name: UnixComponent::new(b"fresh").unwrap(),
		nonce: [0x62; 16],
		source: RemoteSourceObservation::new(length(), 0o100644, 22).unwrap(),
	});
	let refused =
		replay_remote_finalization(journal.bytes.as_slice(), &trust, QUALIFICATION, None).unwrap();
	assert_eq!(refused.phase(), Phase::Sealed);
	assert_eq!(refused.boundary().head, seal);
	assert_eq!(refused.attempts().len(), 1);
	assert!(matches!(
		refused.issue(),
		Some(RemoteReplayIssue::Record {
			problem: RemoteReplayMismatch::Order,
			..
		})
	));
}

#[test]
fn oversized_finalization_payload_is_refused_before_its_first_byte() {
	use std::io::{self, Read};

	use exacopy_journal::remote_download::finalization::MAX_REMOTE_FINALIZATION_BYTES;

	struct CountReads<'counter> {
		input: &'counter [u8],
		count: &'counter mut usize,
	}
	impl Read for CountReads<'_> {
		fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
			let count = self.input.read(buffer)?;
			*self.count += count;
			Ok(count)
		}
	}

	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = Journal::start(&owner);
	journal.prepare(&trust, &owner);
	let prefix_bytes = journal.bytes.len();
	let prepared = journal.prepared;
	let payload = [0; MAX_REMOTE_FINALIZATION_BYTES + 1];
	journal.raw(FrameKind::StageSealed, &payload);

	let mut count = 0;
	let input = CountReads {
		input: &journal.bytes,
		count: &mut count,
	};
	let replay = replay_remote_finalization(input, &trust, QUALIFICATION, None).unwrap();
	assert_eq!(replay.boundary().head, prepared);
	assert!(matches!(
		replay.issue(),
		Some(RemoteReplayIssue::Framing(_))
	));
	assert_eq!(
		count - prefix_bytes,
		56,
		"only the v1 frame header was read"
	);
	assert_eq!(replay.phase(), Phase::Capture);
}

#[test]
fn unknown_signed_policy_is_refused_without_reading_a_journal() {
	use std::io::{self, Read};

	use exacopy_journal::remote_download::RemoteDownloadError;

	struct UnexpectedRead;
	impl Read for UnexpectedRead {
		fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
			panic!("unknown policy must be refused before journal input");
		}
	}

	let mut manifest = owner().manifest().clone();
	manifest.scope.metadata_policy = [0x99; 32];
	let signer = signer();
	let owner = RemoteDownloadOwnerRecord::sign(manifest, &signer).unwrap();
	let key = signer.verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	assert!(matches!(
		replay_remote_finalization(UnexpectedRead, &trust, QUALIFICATION, None),
		Err(RemoteDownloadError::Binding)
	));
}

#[path = "remote_finalization_replay/retirement.rs"]
mod retirement;
