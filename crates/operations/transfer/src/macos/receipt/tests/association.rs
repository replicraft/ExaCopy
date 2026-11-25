use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::{FrameReader, FrameWriter};
use exacopy_journal::{
	DarwinEntryPreparation, DarwinEntryPrepared, DarwinJobPrepared, DarwinNamespaceObservation,
	DarwinOwnerManifest, DarwinOwnerRecord, DarwinPublicationBarriers, DarwinPublicationNames,
	DarwinPublicationOutcome, DarwinPublishObserved, DarwinReceiptCommitted, DarwinRootBinding,
	DarwinSourceTimes, DarwinSourceView, DarwinStageId, DarwinStageObservation, DarwinStageSealed,
	DurableJournal, OwnerProfileId, OwnerToken, TargetObservation,
};

use super::*;
use crate::macos::plan::{PlanAttempt, SourceMetadata, SourcePlanBinding};

struct Prefix {
	verification: Frame,
	metadata: Frame,
	intent: Frame,
	observed: Frame,
	bytes: Vec<u8>,
}

impl Prefix {
	fn new(plan: &DarwinCopyPlan<'_>) -> Self {
		let sample = receipt_fixture().evidence();
		let source_plan = plan.source();
		let destination_plan = plan.destination();
		let state_root = native(15, [23, 24], 12, None, 0, 0);
		let owner = DarwinOwnerRecord::sign(
			DarwinOwnerManifest {
				token: OwnerToken::from_bytes([0x55; 16]).unwrap(),
				job: plan.attempt().job,
				profile: plan.attempt().profile,
				created: OwnerTimestamp::new(0, 0).unwrap(),
				destination_volume: state_root.volume(),
				state_root,
				state_root_uid: OWNER,
				plan_digest: plan.digest(),
			},
			&SigningKey::from_bytes(&[0x56; 32]),
		)
		.unwrap();
		let job = DarwinJobPrepared::new(
			plan.context(),
			&owner,
			DarwinRootBinding {
				id: destination_plan.root_id,
				identity: destination_plan.root_identity,
			},
		)
		.unwrap();
		let stage = DarwinStageObservation {
			id: DarwinStageId::from_bytes([0x57; 16]),
			directory: sample.stage_directory,
			identity: sample.stream.identity,
			component: UnixComponent::new(b"stage").unwrap(),
		};
		let source = DarwinSourceView::new(
			DarwinRootBinding {
				id: source_plan.root_id,
				identity: source_plan.root_identity,
			},
			source_plan.component,
			source_plan.file_identity,
			source_plan.length,
			DarwinSourceTimes {
				accessed_at: sample.metadata.accessed_at,
				modified_at: sample.metadata.modified_at,
				changed_at: OwnerTimestamp::new(9, 0).unwrap(),
			},
			sample.metadata.permissions(),
		)
		.unwrap();
		let prepared = DarwinEntryPrepared::new(
			&job,
			plan.attempt().entry,
			DarwinEntryPreparation {
				source,
				stage,
				target_component: destination_plan.component,
				target_observation: TargetObservation::AbsentObserved,
			},
		)
		.unwrap();

		let mut journal = FrameWriter::new(Vec::new(), ChainHead::start());
		append(&mut journal, FrameKind::JobPrepared, &job.encode());
		let prepared = append(&mut journal, FrameKind::EntryPrepared, &prepared.encode());
		let seal = DarwinStageSealed::new(&prepared, stage.identity, sample.stream.length).unwrap();
		append(&mut journal, FrameKind::StageSealed, &seal.encode());
		let source_stream = DarwinStreamEvidence {
			identity: source_plan.file_identity,
			..sample.stream
		};
		let verification =
			DarwinVerificationRecorded::new(&prepared, &seal, source_stream, sample.stream)
				.unwrap();
		let verified = append(
			&mut journal,
			FrameKind::VerificationRecorded,
			&verification.encode(),
		);
		let metadata = DarwinMetadataRecorded::new(
			&prepared,
			&seal,
			&verification,
			stage.identity,
			sample.metadata,
		)
		.unwrap();
		let metadata_frame = append(
			&mut journal,
			FrameKind::MetadataRecorded,
			&metadata.encode(),
		);
		let intent = DarwinPublishIntent::new(
			NonZeroU64::new(1).unwrap(),
			&prepared,
			&seal,
			&verification,
			&metadata,
		)
		.unwrap();
		let intent = append(&mut journal, FrameKind::PublishIntent, &intent.encode());
		let observed = DarwinPublishObserved::new(
			&intent,
			DarwinPublicationOutcome::Published,
			DarwinPublicationNames {
				target: DarwinNamespaceObservation::Present(stage.identity),
				stage: DarwinNamespaceObservation::Absent,
			},
		)
		.unwrap();
		let observed = append(&mut journal, FrameKind::PublishObserved, &observed.encode());
		Self {
			verification: verified,
			metadata: metadata_frame,
			intent,
			observed,
			bytes: journal.into_inner(),
		}
	}

	fn frames<'frame>(&'frame self, durability: &'frame Frame) -> DarwinReceiptFrames<'frame> {
		DarwinReceiptFrames {
			verification: &self.verification,
			metadata: &self.metadata,
			intent: &self.intent,
			observed: &self.observed,
			durability,
		}
	}

	fn synced(&self, barrier: JournalFileBarrier, kind: FrameKind, payload: &[u8]) -> SyncedFrame {
		static TEST_FILE_SERIAL: AtomicUsize = AtomicUsize::new(0);
		let serial = TEST_FILE_SERIAL.fetch_add(1, Ordering::Relaxed);
		let path = std::env::temp_dir().join(format!(
			"exacopy-apfs-receipt-{}-{serial}.journal",
			std::process::id()
		));
		let mut file = OpenOptions::new()
			.create_new(true)
			.read(true)
			.write(true)
			.open(&path)
			.unwrap();
		let _owned_test_file = TestFile(path);
		file.write_all(&self.bytes).unwrap();
		let mut journal = DurableJournal::resume_first_segment_with_barrier(
			file,
			self.observed.head(),
			self.bytes.len() as u64,
			barrier,
		)
		.unwrap();
		journal.append(kind, payload).unwrap()
	}
}

struct TestFile(PathBuf);

impl Drop for TestFile {
	fn drop(&mut self) {
		let _ = fs::remove_file(&self.0);
	}
}

fn append(writer: &mut FrameWriter<Vec<u8>>, kind: FrameKind, payload: &[u8]) -> Frame {
	let previous = writer.head();
	let mut encoded = FrameWriter::new(Vec::new(), previous);
	encoded.append(kind, payload).unwrap();
	let frame = FrameReader::new(encoded.into_inner().as_slice(), previous)
		.next_frame()
		.unwrap()
		.unwrap();
	assert_eq!(writer.append(kind, payload).unwrap(), frame.head());
	frame
}

fn plan() -> DarwinCopyPlan<'static> {
	let evidence = receipt_fixture().evidence();
	DarwinCopyPlan::new(
		PlanAttempt {
			job: evidence.context.job,
			epoch: evidence.context.epoch,
			entry: evidence.entry,
			profile: OwnerProfileId::from_bytes(uuid(0x58, 4)).unwrap(),
		},
		SourcePlanBinding {
			root_id: RootCapabilityId::from_bytes(uuid(0x59, 4)).unwrap(),
			root_identity: native(-2, [8, 9], 10, None, 0, 0),
			file_identity: evidence.source,
			length: evidence.stream.length.get(),
			metadata: SourceMetadata::new(
				0o600,
				OWNER.get(),
				20,
				ObservedTimestamp::new(-3, 21).unwrap(),
				ObservedTimestamp::new(7, 0).unwrap(),
				ObservedTimestamp::new(9, 0).unwrap(),
			)
			.unwrap(),
			component: UnixComponent::new(b"source").unwrap(),
		},
		evidence.destination,
	)
	.unwrap()
}

fn completed_durability(prefix: &Prefix) -> Frame {
	let evidence = receipt_fixture().evidence();
	let barriers = DarwinPublicationBarriers {
		stage_directory: evidence.stage_directory,
		destination_directory: evidence.destination.root_identity,
	};
	let durability =
		DarwinDurabilityRecorded::new(&prefix.metadata, &prefix.intent, &prefix.observed, barriers)
			.unwrap();
	let mut writer = FrameWriter::new(Vec::new(), prefix.observed.head());
	append(
		&mut writer,
		FrameKind::DurabilityRecorded,
		&durability.encode(),
	)
}

#[test]
fn acceptance_matches_sync_token_exact_frames_plan_and_commitment() {
	let plan = plan();
	let prefix = Prefix::new(&plan);
	let durability = completed_durability(&prefix);
	let frames = prefix.frames(&durability);
	let synced = prefix.synced(
		JournalFileBarrier::DarwinFullFsync,
		durability.kind(),
		durability.payload(),
	);
	let receipt = DarwinCopyReceipt::from_synced_durability(&plan, frames, &synced).unwrap();
	assert_eq!(receipt.durability_frame(), durability.head());
	assert_eq!(receipt.evidence().context.plan_digest, plan.digest());
	assert_eq!(
		receipt.evidence().stream,
		receipt_fixture().evidence().stream
	);
	let encoded = receipt.encode();
	let decoded = DarwinCopyReceipt::decode(&encoded).unwrap();
	decoded.validate_evidence(&plan, frames).unwrap();
	let commitment = DarwinReceiptCommitted::new(&durability, decoded.digest()).unwrap();
	commitment
		.validate_evidence(&durability, receipt.digest())
		.unwrap();

	let substituted = DarwinCopyReceipt::from_evidence(
		DarwinCopyReceiptEvidence {
			stream: DarwinStreamEvidence {
				digest: StreamDigest::from_bytes([0x47; 32]),
				..decoded.evidence().stream
			},
			..decoded.evidence()
		},
		decoded.durability_frame(),
	)
	.unwrap();
	assert_eq!(
		substituted.validate_evidence(&plan, frames),
		Err(DarwinCopyReceiptError::BindingMismatch)
	);
	assert!(
		commitment
			.validate_evidence(&durability, substituted.digest())
			.is_err()
	);
}

#[test]
fn rejects_wrong_sync_operation_profile_or_frame_at_same_sequence() {
	let plan = plan();
	let prefix = Prefix::new(&plan);
	let durability = completed_durability(&prefix);
	for (barrier, kind, payload) in [
		(
			JournalFileBarrier::SyncAll,
			durability.kind(),
			durability.payload(),
		),
		(
			JournalFileBarrier::DarwinFullFsync,
			FrameKind::PublishObserved,
			durability.payload(),
		),
		(
			JournalFileBarrier::DarwinFullFsync,
			durability.kind(),
			b"other",
		),
	] {
		let synced = prefix.synced(barrier, kind, payload);
		assert_eq!(synced.head().sequence(), durability.head().sequence());
		assert_eq!(
			DarwinCopyReceipt::from_synced_durability(&plan, prefix.frames(&durability), &synced),
			Err(DarwinCopyReceiptError::InvalidDurabilityFrame)
		);
	}
}

#[test]
fn rejects_a_different_plan_or_verification_frame() {
	let plan = plan();
	let prefix = Prefix::new(&plan);
	let durability = completed_durability(&prefix);
	let frames = prefix.frames(&durability);
	let receipt = DarwinCopyReceipt::from_journal(&plan, frames).unwrap();
	let different_plan = DarwinCopyPlan::new(
		plan.attempt(),
		plan.source(),
		DestinationPlanBinding {
			component: UnixComponent::new(b"other-target").unwrap(),
			..plan.destination()
		},
	)
	.unwrap();
	assert_eq!(
		receipt.validate_evidence(&different_plan, frames),
		Err(DarwinCopyReceiptError::BindingMismatch)
	);
	assert!(matches!(
		receipt.validate_evidence(
			&plan,
			DarwinReceiptFrames {
				verification: frames.observed,
				..frames
			}
		),
		Err(DarwinCopyReceiptError::Journal(_))
	));
	let mut wrong_order = FrameWriter::new(Vec::new(), frames.metadata.head());
	let wrong_order = append(
		&mut wrong_order,
		FrameKind::VerificationRecorded,
		frames.verification.payload(),
	);
	assert_eq!(
		receipt.validate_evidence(
			&plan,
			DarwinReceiptFrames {
				verification: &wrong_order,
				..frames
			}
		),
		Err(DarwinCopyReceiptError::BindingMismatch)
	);
}
