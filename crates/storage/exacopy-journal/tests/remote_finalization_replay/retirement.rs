//! Exact replay and file-barrier controls for sealed pre-intent capture retirement.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};
use exacopy_journal::remote_download::RemoteDownloadError;
use exacopy_journal::remote_download::retirement::{
	MAX_REMOTE_RETIREMENT_BYTES, RemoteCaptureRetired, RemoteRetirementObservation,
};
use exacopy_journal::{DurableJournal, NamespaceObservation};

use super::*;

const GRANT: [u8; 32] = [0x72; 32];
const NEXT_STAGE: LinuxFileIdentity = LinuxFileIdentity::new(7, 14);

fn observed(owner: &RemoteDownloadOwnerRecord) -> RemoteRetirementObservation<'_> {
	let destination = &owner.manifest().scope.destination;
	RemoteRetirementObservation {
		directory: DIRECTORY,
		stage_name: UnixComponent::new(b"attempt").unwrap(),
		stage: STAGE,
		target: RemotePublishTarget {
			root: destination.root(),
			parent: destination.parent(),
			component: UnixComponent::new(destination.target()).unwrap(),
		},
		target_observation: NamespaceObservation::Absent,
		qualification_digest: QUALIFICATION,
		grant_digest: GRANT,
	}
}

fn sealed(owner: &RemoteDownloadOwnerRecord, trust: &RemoteBootstrapTrust<'_>) -> Journal {
	let mut journal = Journal::start(owner);
	journal.prepare(trust, owner);
	journal.checkpoint(1, 0);
	journal.final_record(Final::StageSealed {
		directory: DIRECTORY,
		length: length(),
	});
	journal
}

fn allocate(journal: &mut Journal, next: RemoteEpochs) -> ChainHead {
	journal.capture(Capture::StageAllocated {
		previous: Some(journal.epochs),
		next,
		name: UnixComponent::new(b"fresh").unwrap(),
		nonce: [0x62; 16],
		source: RemoteSourceObservation::new(length(), 0o100600, 23).unwrap(),
	})
}

fn replay<'owner>(
	journal: &Journal,
	trust: &RemoteBootstrapTrust<'owner>,
) -> exacopy_journal::remote_download::finalization_replay::RemoteFinalizationReplay<'owner> {
	replay_remote_finalization(journal.bytes.as_slice(), trust, QUALIFICATION, None).unwrap()
}

#[test]
fn synced_retirement_admits_fresh_attempt_and_preserves_old_stage() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = sealed(&owner, &trust);
	let old_seal = journal.head;
	let old_prepared = journal.prepared;
	let checked = replay(&journal, &trust);
	let candidate = checked
		.retirement_candidate(GRANT, observed(&owner))
		.unwrap();
	let payload = candidate.record().encode().unwrap();
	assert_eq!(candidate.record().predecessor(), journal.head);
	let mut writer = writer::<true>(&journal);
	let ack = writer
		.append(FrameKind::RemoteCaptureRetired, &payload)
		.unwrap();
	let retirement = candidate.validate_synced(&ack).unwrap();
	assert_eq!(
		journal.raw(FrameKind::RemoteCaptureRetired, &payload),
		retirement
	);

	let retired = replay(&journal, &trust);
	assert_eq!(retired.phase(), Phase::Retired);
	assert_eq!(retired.boundary().head, retirement);
	assert_eq!(retired.retirements()[0].seal, old_seal);
	assert_eq!(retired.retirements()[0].prepared, old_prepared);
	assert_eq!(retired.retirements()[0].stage, STAGE);
	assert_eq!(retired.retirements()[0].grant_digest, GRANT);
	assert_eq!(retired.retirements()[0].qualification_digest, QUALIFICATION);
	assert_eq!(retired.attempts()[0].prepared().unwrap().file, STAGE);
	assert!(
		retired
			.retirement_candidate(GRANT, observed(&owner))
			.is_err()
	);

	let next = RemoteEpochs {
		run: NonZeroU64::new(2).unwrap(),
		source: NonZeroU64::new(8).unwrap(),
	};
	let allocation = allocate(&mut journal, next);
	let prepared = journal.capture(Capture::EntryPrepared {
		allocation,
		epochs: next,
		nonce: [0x62; 16],
		stage_directory: DIRECTORY,
		stage: NEXT_STAGE,
	});
	let restarted = replay(&journal, &trust);
	assert_eq!(restarted.phase(), Phase::Capture);
	assert_eq!(restarted.boundary().head, prepared);
	assert_eq!(restarted.retirements(), retired.retirements());
	assert_eq!(restarted.attempts().len(), 2);
	assert_eq!(restarted.attempts()[0].covered_extent(), 2);
	assert_eq!(restarted.attempts()[1].covered_extent(), 0);
	assert_eq!(restarted.attempts()[1].epochs(), next);
	assert_eq!(restarted.attempts()[1].prepared().unwrap().file, NEXT_STAGE);
	assert!(restarted.issue().is_none());

	journal.capture(Capture::RangeCheckpoint {
		prepared: old_prepared,
		epochs: journal.epochs,
		ordinal: 1,
		offset: 0,
		length: 2,
		digest: StreamDigest::from_bytes([0x41; 32]),
	});
	let stale = replay(&journal, &trust);
	assert_eq!(stale.boundary().head, prepared);
	assert!(stale.issue().is_some());
}

#[test]
fn refuses_authorization_and_acknowledgement_substitution() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let journal = sealed(&owner, &trust);
	let checked = replay(&journal, &trust);
	let mut facts = observed(&owner);
	assert!(checked.retirement_candidate([0x73; 32], facts).is_err());
	facts.grant_digest = [0; 32];
	assert!(checked.retirement_candidate([0; 32], facts).is_err());
	facts = observed(&owner);
	facts.stage_name = UnixComponent::new(b"Attempt").unwrap();
	assert_eq!(
		checked.retirement_candidate(GRANT, facts).unwrap_err(),
		RemoteDownloadError::Binding
	);
	facts = observed(&owner);
	facts.stage = NEXT_STAGE;
	assert!(checked.retirement_candidate(GRANT, facts).is_err());
	facts = observed(&owner);
	facts.qualification_digest = [0x77; 32];
	assert!(checked.retirement_candidate(GRANT, facts).is_err());
	facts = observed(&owner);
	facts.target.component = UnixComponent::new(b"foreign").unwrap();
	assert!(checked.retirement_candidate(GRANT, facts).is_err());
	for outcome in [
		NamespaceObservation::Present(NEXT_STAGE),
		NamespaceObservation::Unobserved,
	] {
		facts = observed(&owner);
		facts.target_observation = outcome;
		assert!(checked.retirement_candidate(GRANT, facts).is_err());
	}

	let candidate = checked
		.retirement_candidate(GRANT, observed(&owner))
		.unwrap();
	let mut payload = candidate.record().encode().unwrap();
	let offset = payload
		.windows(32)
		.position(|bytes| bytes == GRANT)
		.unwrap();
	payload[offset] ^= 1;
	assert!(RemoteCaptureRetired::decode(&payload).is_ok());
	let ack = writer::<true>(&journal)
		.append(FrameKind::RemoteCaptureRetired, &payload)
		.unwrap();
	assert_eq!(
		candidate.validate_synced(&ack),
		Err(RemoteDownloadError::FrameBinding)
	);

	let candidate = checked
		.retirement_candidate(GRANT, observed(&owner))
		.unwrap();
	let payload = candidate.record().encode().unwrap();
	let wrong_barrier = writer::<false>(&journal)
		.append(FrameKind::RemoteCaptureRetired, &payload)
		.unwrap();
	assert_eq!(
		candidate.validate_synced(&wrong_barrier),
		Err(RemoteDownloadError::FrameBinding)
	);
}

#[test]
fn accepts_only_pre_intent_and_clear_prefixes() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = sealed(&owner, &trust);
	let clear = replay(&journal, &trust);
	let sealed_offset = journal.bytes.len();
	let encoded = clear
		.retirement_candidate(GRANT, observed(&owner))
		.unwrap()
		.record()
		.encode()
		.unwrap();
	journal.bytes.extend_from_slice(b"EXA");
	let torn = replay(&journal, &trust);
	assert_eq!(torn.phase(), Phase::Sealed);
	assert!(torn.issue().is_some());
	assert!(torn.retirement_candidate(GRANT, observed(&owner)).is_err());
	journal.bytes.truncate(sealed_offset);
	let seal_head = journal.head;
	journal.raw(FrameKind::RemoteCaptureRetired, &encoded);
	let kind = sealed_offset + 10;
	journal.bytes[kind..kind + 2].copy_from_slice(&u16::MAX.to_le_bytes());
	let unknown = replay(&journal, &trust);
	assert_eq!(unknown.boundary().head, seal_head);
	assert!(matches!(
		unknown.issue(),
		Some(RemoteReplayIssue::Framing(
			exacopy_journal::frame::FrameReadError::Corrupt {
				problem: exacopy_journal::frame::FrameProblem::UnsupportedKind(u16::MAX),
				..
			}
		))
	));
	assert!(
		unknown
			.retirement_candidate(GRANT, observed(&owner))
			.is_err()
	);

	for outcome in [
		None,
		Some(RemotePublicationObservation::Conflict),
		Some(RemotePublicationObservation::Uncertain {
			target: exacopy_journal::NamespaceObservation::Unobserved,
			stage: exacopy_journal::NamespaceObservation::Unobserved,
		}),
	] {
		let mut sent = Journal::start(&owner);
		sent.prepare(&trust, &owner);
		sent.intent(&owner);
		if let Some(outcome) = outcome {
			sent.final_record(Final::PublishObserved(outcome));
		}
		let terminal = sent.head;
		assert!(
			replay(&sent, &trust)
				.retirement_candidate(GRANT, observed(&owner))
				.is_err()
		);
		sent.raw(FrameKind::RemoteCaptureRetired, &encoded);
		let refused = replay(&sent, &trust);
		assert_eq!(refused.boundary().head, terminal);
		assert!(refused.retirements().is_empty());
		assert!(refused.issue().is_some());
	}
}

#[test]
fn substituted_heads_scope_stage_and_qualification_never_retire_capture() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let sequence = sealed(&owner, &trust);
	let checked = replay(&sequence, &trust);
	let payload = checked
		.retirement_candidate(GRANT, observed(&owner))
		.unwrap()
		.record()
		.encode()
		.unwrap();
	assert_eq!(
		RemoteCaptureRetired::decode(&payload)
			.unwrap()
			.encode()
			.unwrap(),
		payload
	);
	let scope = owner.manifest().scope.digest().unwrap();
	let wrong = [
		sequence.prepared.digest().to_vec(),
		scope.as_bytes().to_vec(),
		STAGE.inode().to_le_bytes().to_vec(),
		QUALIFICATION.to_vec(),
		GRANT.to_vec(),
	];
	for (index, original) in wrong.iter().enumerate() {
		let mut altered = payload.clone();
		let offset = altered
			.windows(original.len())
			.position(|bytes| bytes == original)
			.unwrap();
		if index == 4 {
			altered[offset..offset + original.len()].fill(0);
		} else {
			altered[offset] ^= 1;
		}
		let mut journal = sealed(&owner, &trust);
		let old = journal.head;
		journal.raw(FrameKind::RemoteCaptureRetired, &altered);
		let refused = replay(&journal, &trust);
		assert_eq!(refused.boundary().head, old, "mutation {index}");
		assert_eq!(refused.phase(), Phase::Sealed, "mutation {index}");
		assert!(refused.issue().is_some(), "mutation {index}");
	}
}

#[test]
fn exact_cuts_and_profile_limit_preserve_accepted_boundary() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = sealed(&owner, &trust);
	let old = journal.head;
	let accepted_end = journal.bytes.len();
	let payload = replay(&journal, &trust)
		.retirement_candidate(GRANT, observed(&owner))
		.unwrap()
		.record()
		.encode()
		.unwrap();
	for end in 0..payload.len() {
		assert!(
			RemoteCaptureRetired::decode(&payload[..end]).is_err(),
			"payload cut {end}"
		);
	}
	for index in [payload.len() - 1, payload.len() - 2] {
		let mut altered = payload.clone();
		altered[index] = 0;
		assert!(RemoteCaptureRetired::decode(&altered).is_err());
	}
	journal.raw(FrameKind::RemoteCaptureRetired, &payload);
	for end in accepted_end + 1..journal.bytes.len() {
		let cut =
			replay_remote_finalization(&journal.bytes[..end], &trust, QUALIFICATION, None).unwrap();
		assert_eq!(cut.boundary().head, old, "frame cut {end}");
		assert!(cut.issue().is_some(), "frame cut {end}");
	}

	let mut journal = sealed(&owner, &trust);
	journal.raw(
		FrameKind::RemoteCaptureRetired,
		&[0; MAX_REMOTE_RETIREMENT_BYTES + 1],
	);
	let mut input = journal.bytes.as_slice();
	let refused = replay_remote_finalization(&mut input, &trust, QUALIFICATION, None).unwrap();
	assert_eq!(journal.bytes.len() - input.len() - accepted_end, 56);
	assert_eq!(refused.boundary().head, old);
	assert!(refused.issue().is_some());
}

struct Segment<const FULL: bool>(Cursor<Vec<u8>>);

impl<const FULL: bool> Read for Segment<FULL> {
	fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
		self.0.read(data)
	}
}

impl<const FULL: bool> Write for Segment<FULL> {
	fn write(&mut self, data: &[u8]) -> io::Result<usize> {
		self.0.write(data)
	}
	fn flush(&mut self) -> io::Result<()> {
		self.0.flush()
	}
}

impl<const FULL: bool> Seek for Segment<FULL> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.0.seek(position)
	}
}

impl<const FULL: bool> JournalSegment for Segment<FULL> {
	const BARRIER: JournalFileBarrier = if FULL {
		JournalFileBarrier::SyncAll
	} else {
		JournalFileBarrier::DarwinFullFsync
	};

	fn regular_length(&self) -> io::Result<Option<u64>> {
		Ok(Some(u64::try_from(self.0.get_ref().len()).unwrap()))
	}

	fn sync(&self) -> io::Result<()> {
		Ok(())
	}
}

fn writer<const FULL: bool>(journal: &Journal) -> DurableJournal<Segment<FULL>> {
	DurableJournal::resume_first_segment(
		Segment(Cursor::new(journal.bytes.clone())),
		journal.head,
		u64::try_from(journal.bytes.len()).unwrap(),
	)
	.unwrap()
}

#[test]
fn later_pre_intent_metadata_can_retire_without_admitting_stale_epochs() {
	let owner = owner();
	let key = signer().verifying_key();
	let trust = RemoteBootstrapTrust::new(&owner, profile(), &key).unwrap();
	let mut journal = sealed(&owner, &trust);
	let seal = journal.head;
	let digest = StreamDigest::from_bytes([0x13; 32]);
	journal.final_record(Final::VerificationRecorded {
		length: length(),
		source: digest,
		stage: digest,
	});
	let verified = replay(&journal, &trust);
	assert_eq!(verified.phase(), Phase::Verified);
	assert!(
		verified
			.retirement_candidate(GRANT, observed(&owner))
			.is_ok()
	);
	journal.final_record(Final::MetadataRecorded(RemoteLocalMetadata {
		uid: 1000,
		gid: 1001,
	}));
	let metadata = replay(&journal, &trust);
	assert_eq!(metadata.phase(), Phase::MetadataReady);
	let retired = metadata
		.retirement_candidate(GRANT, observed(&owner))
		.unwrap();
	let payload = retired.record().encode().unwrap();
	let retirement = journal.raw(FrameKind::RemoteCaptureRetired, &payload);
	journal.capture(Capture::StageAllocated {
		previous: None,
		next: journal.epochs,
		name: UnixComponent::new(b"stale-epoch").unwrap(),
		nonce: [0x62; 16],
		source: RemoteSourceObservation::new(length(), 0o100600, 23).unwrap(),
	});
	let refused = replay(&journal, &trust);
	assert_eq!(refused.phase(), Phase::Retired);
	assert_eq!(refused.retirements()[0].seal, seal);
	assert_eq!(refused.boundary().head, retirement);
	assert_eq!(refused.attempts().len(), 1);
	assert!(refused.issue().is_some());
}
