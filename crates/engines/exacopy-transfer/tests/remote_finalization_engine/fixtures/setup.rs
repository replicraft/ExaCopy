use std::sync::OnceLock;

use ed25519_dalek::VerifyingKey;
use exacopy_journal::NamespaceObservation;
use exacopy_journal::remote_download::RemoteUncertainBoundary;
use exacopy_journal::remote_download::finalization::{
	RemoteFinalizationBinding, RemoteFinalizationBody, RemoteFinalizationRecord,
	RemotePublishTarget,
};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, replay_remote_finalization,
};
use exacopy_journal::remote_download::replay::RemoteReplayIssue;
use exacopy_journal::remote_download::retirement::RemoteRetirementObservation;

use super::*;

pub const RETIRED_STAGE: LinuxFileIdentity = LinuxFileIdentity::new(7, 14);
const RETIRED_NAME: &[u8] = b"retired-part";
const RETIRED_NONCE: [u8; 16] = [54; 16];

#[derive(Clone, Copy)]
pub enum ReplayBeforeFinalization {
	Sealed,
	Uncertain,
	Torn,
	WrongQualification,
}

pub struct TestRun {
	owner: RemoteDownloadOwnerRecord,
	allocation: Frame,
	prepared: Frame,
	capture: ObservedCapture<Closed>,
	journal: Journal,
	authority: Authority,
	receipts: Receipts,
	pub bytes: Bytes,
	pub tape: Tape,
}

impl TestRun {
	pub fn owner(&self) -> &RemoteDownloadOwnerRecord {
		&self.owner
	}

	pub fn new(data: &'static [u8], fault: Fault) -> Self {
		Self::for_job(data, fault, JOB)
	}

	pub fn for_job(data: &'static [u8], fault: Fault, job_id: [u8; 16]) -> Self {
		Self::prepare(data, fault, job_id, false)
	}

	pub fn after_retirement(data: &'static [u8]) -> Self {
		Self::prepare(data, Fault::None, JOB, true)
	}

	fn prepare(data: &'static [u8], fault: Fault, job_id: [u8; 16], retire: bool) -> Self {
		let tape = Tape::default();
		let bytes = Bytes::default();
		let mut journal = Journal {
			bytes: Rc::clone(&bytes),
			writer: DurableJournal::from_new_segment(MemorySegment(Rc::clone(&bytes))).unwrap(),
			boundary: RemoteReplayBoundary {
				head: ChainHead::start(),
				offset: 0,
			},
			fault,
			tape: Rc::clone(&tape),
		};
		let policy = admit_sftp_metadata(RemoteMetadataSelection::SftpDataOnlyV1).unwrap();
		let signer = SigningKey::from_bytes(&[52; 32]);
		let key = signer.verifying_key();
		let profile = OwnerProfileId::from_bytes([22; 16]).unwrap();
		let owner = owner(&signer, profile, policy.digest(), job_id);
		let trust = RemoteBootstrapTrust::new(&owner, profile, &key).unwrap();
		let context = RemoteDownloadContext {
			owner: owner.digest(),
			job: owner.manifest().job,
			entry: owner.manifest().scope.entry,
		};
		let scope = owner.manifest().scope.digest().unwrap();
		let job = journal.prefix(context, Body::JobPrepared { scope });
		let signed = trust.sign(&job, DIRECTORY, &signer).unwrap();
		let _ = journal.write_entry(FrameKind::StageDirectoryPrepared, signed);
		let previous = retire.then(|| {
			record_retirement(
				&mut journal,
				&trust,
				&owner.manifest().scope.destination,
				context,
			)
		});
		let epochs = RemoteEpochs {
			run: NonZeroU64::new(if retire { 2 } else { 1 }).unwrap(),
			source: NonZeroU64::new(8).unwrap(),
		};
		let length = u64::try_from(data.len()).unwrap();
		let allocation = journal.prefix(
			context,
			Body::StageAllocated {
				previous,
				next: epochs,
				name: UnixComponent::new(b"part").unwrap(),
				nonce: NONCE,
				source: RemoteSourceObservation::new(
					StreamLength::new(length).unwrap(),
					0o100644,
					1,
				)
				.unwrap(),
			},
		);
		let prepared = journal.prefix(
			context,
			Body::EntryPrepared {
				allocation: allocation.head(),
				epochs,
				nonce: NONCE,
				stage_directory: DIRECTORY,
				stage: STAGE,
			},
		);
		let mut source = Source(data, SourceEpoch::new(epochs.source));
		let stage = Stage(
			Vec::new(),
			RemoteReadyStageFacts {
				binding: CopyBinding::new(
					JobId::try_from_bytes(job_id).unwrap(),
					EntryId::new(1),
					RunEpoch::new(epochs.run.get()),
					StageId::from_bytes(NONCE),
				),
				stage: STAGE,
				directory: DIRECTORY,
				parent: PARENT,
				length,
				mode: 0o600,
				metadata: RemoteLocalMetadata {
					uid: 1000,
					gid: 1000,
				},
			},
			fault,
			Rc::clone(&tape),
		);
		let mut checkpoints = Checkpoints {
			journal: &mut journal,
			context,
			prepared: prepared.head(),
			epochs,
		};
		let capture = ready(capture_live(
			&mut source,
			SourceEpoch::new(epochs.source),
			stage,
			&mut checkpoints,
			&mut [0; 64],
		))
		.unwrap();
		let authority = Authority(
			RemotePublicationAuthority {
				scope,
				grant: GRANT,
				qualification: QUALIFICATION,
				parent: PARENT,
			},
			fault,
			Rc::clone(&tape),
			0,
		);
		let receipts = Receipts::new(fault, Rc::clone(&tape));
		Self {
			owner,
			allocation,
			prepared,
			capture,
			journal,
			authority,
			receipts,
			bytes,
			tape,
		}
	}

	pub fn with_capture_from(mut self, donor: Self) -> Self {
		self.capture = donor.capture;
		self
	}

	pub fn execute(self) -> (TestResult, Vec<u8>) {
		self.run(QUALIFICATION)
	}

	pub fn with_refused_prefix(
		mut self,
		prefix: ReplayBeforeFinalization,
	) -> (TestResult, Vec<u8>) {
		let record = RemoteDownloadRecord::from_frame(&self.allocation).unwrap();
		let Body::StageAllocated {
			next: epochs,
			source,
			..
		} = record.body()
		else {
			panic!("stage allocation");
		};
		match prefix {
			ReplayBeforeFinalization::Sealed => {
				append_seal(
					&mut self.journal,
					RemoteFinalizationBinding {
						context: record.context(),
						prepared: self.prepared.head(),
						epochs,
						stage: STAGE,
					},
					source.length(),
				);
			}
			ReplayBeforeFinalization::Uncertain => {
				let _ = self.journal.prefix(
					record.context(),
					Body::FailureRecorded {
						attempt: self.prepared.head(),
						epochs,
						boundary: RemoteUncertainBoundary::TerminalSource,
					},
				);
			}
			ReplayBeforeFinalization::Torn => self.bytes.borrow_mut().get_mut().push(0),
			ReplayBeforeFinalization::WrongQualification => {}
		}
		let qualification = match prefix {
			ReplayBeforeFinalization::WrongQualification => [43; 32],
			_ => QUALIFICATION,
		};
		let replay = selected_replay(
			&self.owner,
			self.bytes.borrow().get_ref(),
			qualification,
			None,
		);
		match prefix {
			ReplayBeforeFinalization::Sealed => {
				assert_eq!(replay.phase(), RemoteFinalizationPhase::Sealed);
				assert!(replay.issue().is_none());
			}
			ReplayBeforeFinalization::Uncertain => {
				assert!(matches!(
					replay.issue(),
					Some(RemoteReplayIssue::RecordedUncertainty)
				));
			}
			ReplayBeforeFinalization::Torn => {
				assert!(matches!(
					replay.issue(),
					Some(RemoteReplayIssue::Framing(_))
				));
			}
			ReplayBeforeFinalization::WrongQualification => {
				assert_eq!(replay.phase(), RemoteFinalizationPhase::Capture);
				assert!(replay.issue().is_none());
			}
		}
		self.run(qualification)
	}

	fn run(mut self, expected_qualification: [u8; 32]) -> (TestResult, Vec<u8>) {
		let replay = selected_replay(
			&self.owner,
			self.bytes.borrow().get_ref(),
			expected_qualification,
			None,
		);
		let result = finalize_capture(
			RemoteFinalizationRequest {
				owner: &self.owner,
				replay: &replay,
				allocation: &self.allocation,
				prepared: &self.prepared,
				authority: self.authority.0,
				policy: admit_sftp_metadata(RemoteMetadataSelection::SftpDataOnlyV1).unwrap(),
			},
			self.capture,
			&mut self.journal,
			&mut self.authority,
			&self.receipts,
		);
		let receipt = self.receipts.bytes.borrow().to_vec();
		(result, receipt)
	}
}

pub(super) fn selected_replay<'owner>(
	owner: &'owner RemoteDownloadOwnerRecord,
	journal: &[u8],
	expected_qualification: [u8; 32],
	receipt: Option<&[u8]>,
) -> RemoteFinalizationReplay<'owner> {
	static KEY: OnceLock<VerifyingKey> = OnceLock::new();
	let key = KEY.get_or_init(|| SigningKey::from_bytes(&[52; 32]).verifying_key());
	let trust = RemoteBootstrapTrust::new(owner, owner.manifest().profile, key).unwrap();
	replay_remote_finalization(journal, &trust, expected_qualification, receipt).unwrap()
}

fn append_seal(journal: &mut Journal, binding: RemoteFinalizationBinding, length: StreamLength) {
	let body = RemoteFinalizationBody::StageSealed {
		directory: DIRECTORY,
		length,
	};
	let seal = RemoteFinalizationRecord::new(binding, journal.boundary.head, body).unwrap();
	let _ = journal.write_entry(FrameKind::StageSealed, seal.encode().unwrap());
}

fn record_retirement(
	journal: &mut Journal,
	trust: &RemoteBootstrapTrust<'_>,
	destination: &RemoteDownloadDestination,
	context: RemoteDownloadContext,
) -> RemoteEpochs {
	let epochs = RemoteEpochs {
		run: NonZeroU64::new(1).unwrap(),
		source: NonZeroU64::new(7).unwrap(),
	};
	let name = UnixComponent::new(RETIRED_NAME).unwrap();
	let length = StreamLength::new(3).unwrap();
	let allocation = journal.prefix(
		context,
		Body::StageAllocated {
			previous: None,
			next: epochs,
			name,
			nonce: RETIRED_NONCE,
			source: RemoteSourceObservation::new(length, 0o100644, 1).unwrap(),
		},
	);
	let prepared = journal.prefix(
		context,
		Body::EntryPrepared {
			allocation: allocation.head(),
			epochs,
			nonce: RETIRED_NONCE,
			stage_directory: DIRECTORY,
			stage: RETIRED_STAGE,
		},
	);
	let _ = journal.prefix(
		context,
		Body::RangeCheckpoint {
			prepared: prepared.head(),
			epochs,
			ordinal: 1,
			offset: 0,
			length: length.get(),
			digest: exacopy_journal::StreamDigest::from_bytes(*blake3::hash(b"old").as_bytes()),
		},
	);
	append_seal(
		journal,
		RemoteFinalizationBinding {
			context,
			prepared: prepared.head(),
			epochs,
			stage: RETIRED_STAGE,
		},
		length,
	);
	let sealed = replay_remote_finalization(
		journal.bytes.borrow().get_ref().as_slice(),
		trust,
		QUALIFICATION,
		None,
	)
	.unwrap();
	let retirement = sealed
		.retirement_candidate(
			GRANT,
			RemoteRetirementObservation {
				directory: DIRECTORY,
				stage_name: name,
				stage: RETIRED_STAGE,
				target: RemotePublishTarget {
					root: destination.root(),
					parent: destination.parent(),
					component: UnixComponent::new(destination.target()).unwrap(),
				},
				target_observation: NamespaceObservation::Absent,
				qualification_digest: QUALIFICATION,
				grant_digest: GRANT,
			},
		)
		.unwrap();
	let payload = retirement.record().encode().unwrap();
	let (frame, synced) = journal.write_entry(FrameKind::RemoteCaptureRetired, payload);
	assert_eq!(retirement.validate_synced(&synced).unwrap(), frame.head());
	epochs
}

type TestResult = RemoteFinalizationResult<&'static str, &'static str, &'static str, &'static str>;

fn owner(
	signer: &SigningKey,
	profile: OwnerProfileId,
	policy: [u8; 32],
	job_id: [u8; 16],
) -> RemoteDownloadOwnerRecord {
	let source = RemoteDownloadSource::new(
		SshAuthority::new("transfer.example", NonZeroU16::new(22).unwrap(), "reader").unwrap(),
		[44; 32],
		RemoteDownloadRoute::Direct,
		b"source",
	)
	.unwrap();
	let mut root_bytes = [88; 16];
	root_bytes[8] = 0x94;
	let destination = RemoteDownloadDestination::new(
		RootCapabilityId::from_bytes(root_bytes).unwrap(),
		PARENT,
		UnixComponent::new(b"target").unwrap(),
	);
	let scope = RemoteDownloadScope::new(
		JournalEntryId::from_bytes([33; 16]),
		source,
		destination,
		StreamLength::new(1024).unwrap(),
		policy,
		RemoteDownloadDurability::ProcessCrash,
	)
	.unwrap();
	let owner = RemoteDownloadOwner::new(
		OwnerToken::from_bytes([11; 16]).unwrap(),
		JournalJobId::from_bytes(job_id).unwrap(),
		profile,
		OwnerTimestamp::new(0, 0).unwrap(),
		LinuxFileIdentity::new(7, 11),
		scope,
	)
	.unwrap();
	RemoteDownloadOwnerRecord::sign(owner, signer).unwrap()
}

fn ready<F: Future>(future: F) -> F::Output {
	match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
		Poll::Ready(result) => result,
		Poll::Pending => panic!("memory capture must complete immediately"),
	}
}
