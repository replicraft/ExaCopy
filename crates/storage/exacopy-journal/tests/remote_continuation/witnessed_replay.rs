use std::cell::Cell;
use std::io::{self, Read};

use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationPhase;
use exacopy_journal::remote_download::replay::{RemoteReplayIssue, RemoteReplayMismatch};
use exacopy_journal::remote_download::witness::records::{
	RemoteRetainedWitness, RemoteWitnessedOutcome,
};
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase as Phase,
	RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};

use super::*;

const FRESH: [u8; 32] = [0x85; 32];

fn recorded(label: &str) -> Vec<u8> {
	include_str!("witnessed_replay.hex")
		.lines()
		.find_map(|line| {
			let (name, bytes) = line.split_once(' ')?;
			(name == label).then(|| hex(bytes))
		})
		.unwrap()
}

fn scan(run: &Transcript, bytes: impl Read, fresh: [u8; 32]) -> RemoteWitnessedCloseoutReplay {
	replay_remote_witnessed_closeout(
		bytes,
		&run.fixture.trust(),
		&RemoteWitnessedReplaySelection {
			initial_v1_qualification: QUALIFICATION,
			fresh_v1_qualification: fresh,
			qualification: &run.qualification,
			grant_digest: [0x72; 32],
		},
	)
	.unwrap()
}

fn boundary_of(bytes: &[u8], wanted: FrameKind) -> RemoteReplayBoundary {
	let mut reader = FrameReader::new(bytes, ChainHead::start());
	while let Some(frame) = reader.next_frame().unwrap() {
		if frame.kind() == wanted {
			return RemoteReplayBoundary {
				head: frame.head(),
				offset: reader.offset(),
			};
		}
	}
	panic!("independent fixture lacks {wanted:?}");
}

fn assert_clean(replay: &RemoteWitnessedCloseoutReplay, bytes: &[u8], phase: Phase) {
	assert!(replay.issue().is_none(), "{:?}", replay.issue());
	assert_eq!(replay.phase(), phase);
	assert_eq!(
		replay.boundary().offset,
		u64::try_from(bytes.len()).unwrap()
	);
}

#[test]
fn closed_witnessed_transcripts_bind_both_observation_channels_and_exact_receipt() {
	let run = Transcript::read(false);
	for (label, receipt_label, recovered) in [
		("published", "receipt", false),
		("recovered-published", "recovered-receipt", true),
	] {
		let bytes = recorded(label);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		assert_clean(&replay, &bytes, Phase::ReceiptCommitted);
		assert_eq!(replay.pass_count(), 2);
		assert_eq!(replay.attempts().len(), 1);
		assert_eq!(
			matches!(
				replay.observed_outcome(),
				Some(RemoteWitnessedOutcome::Recovered { .. })
			),
			recovered,
		);
		assert!(replay.witness().is_some());
		let ready = replay.receipt_ready().unwrap();
		let receipt = recorded(receipt_label);
		assert!(replay.matches_committed_receipt(ready.receipt(), &receipt));
		assert!(!replay.matches_committed_receipt(LinuxFileIdentity::new(7, 18), &receipt));
		assert!(!replay.matches_committed_receipt(ready.receipt(), &receipt[..receipt.len() - 1]));
		assert!(replay.active_prefix_history().is_err());

		let witness = boundary_of(&bytes, FrameKind::RemoteWitnessIntent);
		let partial = &bytes[..usize::try_from(witness.offset).unwrap()];
		assert_clean(
			&scan(&run, partial, FRESH),
			partial,
			Phase::WitnessIntentRequiresInspection,
		);
		let ready = boundary_of(&bytes, FrameKind::RemoteReceiptReady);
		let partial = &bytes[..usize::try_from(ready.offset).unwrap()];
		assert_clean(
			&scan(&run, partial, FRESH),
			partial,
			Phase::ReceiptReadyRequiresInspection,
		);
	}
}

#[test]
fn uncertain_conflict_and_genuine_failure_latch_before_later_effects() {
	let run = Transcript::read(false);
	for (label, successor, phase) in [
		("conflict", "conflict-then-durability", Phase::Conflict),
		("uncertain", "uncertain-then-durability", Phase::Uncertain),
		("pre-intent-failure", "failure-then-seal", Phase::Uncertain),
	] {
		let bytes = recorded(label);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		assert_eq!(replay.phase(), phase);
		assert_eq!(
			replay.boundary().offset,
			u64::try_from(bytes.len()).unwrap()
		);
		assert_eq!(
			replay.recorded_failure().is_some(),
			label == "pre-intent-failure"
		);
		if phase == Phase::Uncertain {
			assert!(matches!(
				replay.issue(),
				Some(RemoteReplayIssue::RecordedUncertainty)
			));
		}
		let prior = replay.boundary();
		let next = recorded(successor);
		let attempted = scan(&run, next.as_slice(), FRESH);
		assert_eq!(attempted.boundary(), prior);
		assert_eq!(attempted.phase(), phase);
		let Some(RemoteReplayIssue::Record { problem, .. }) = attempted.issue() else {
			panic!("wrong diagnostic: {:?}", attempted.issue());
		};
		let reason = if phase == Phase::Uncertain {
			RemoteReplayMismatch::AfterUncertainty
		} else {
			RemoteReplayMismatch::UnsupportedKind
		};
		assert_eq!(*problem, reason);
		assert!(attempted.active_prefix_history().is_err());
		assert!(attempted.receipt_ready().is_none());
	}
	let false_failure = recorded("false-terminal-source-after-witness");
	let refused = scan(&run, false_failure.as_slice(), FRESH);
	assert_eq!(refused.phase(), Phase::WitnessIntentRequiresInspection);
	assert!(refused.recorded_failure().is_none());
	assert!(matches!(
		refused.issue(),
		Some(RemoteReplayIssue::Record {
			problem: RemoteReplayMismatch::FailureBinding,
			..
		})
	));
}

#[test]
fn retirement_preserves_witness_and_enforces_global_epochs_and_archive_role() {
	let run = Transcript::read(false);
	for label in [
		"retire-unwitnessed",
		"retire-absent-at-intent",
		"retire-preserved",
	] {
		let bytes = recorded(label);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		assert_clean(&replay, &bytes, Phase::Retired);
		let retired = replay.retirements()[0];
		assert_eq!(replay.boundary().head, retired.head);
		assert!(match label {
			"retire-unwitnessed" => retired.witness == RemoteRetainedWitness::NoIntent,
			"retire-absent-at-intent" =>
				matches!(retired.witness, RemoteRetainedWitness::AbsentAfterIntent(_)),
			_ => matches!(retired.witness, RemoteRetainedWitness::Preserved { .. }),
		});
	}
	let bytes = recorded("fresh-unbound");
	let unbound = scan(&run, bytes.as_slice(), FRESH);
	assert_clean(&unbound, &bytes, Phase::FreshAllocationUnbound);
	assert_eq!(unbound.attempts()[1].epochs().run.get(), 3);
	assert_eq!(unbound.pass_count(), 3);
	let alternate = recorded("fresh-unbound-then-allocation");
	let refused = scan(&run, alternate.as_slice(), FRESH);
	assert_eq!(refused.boundary(), unbound.boundary());
	assert!(refused.issue().is_some());

	let bytes = recorded("fresh-v1-intent");
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_clean(
		&replay,
		&bytes,
		Phase::Legacy(RemoteFinalizationPhase::Intent),
	);
	let wrong_archive = scan(&run, bytes.as_slice(), QUALIFICATION);
	assert_eq!(
		wrong_archive.phase(),
		Phase::Legacy(RemoteFinalizationPhase::MetadataReady)
	);
	assert!(wrong_archive.issue().is_some());

	let bytes = recorded("fresh-v1-then-v2");
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_clean(&replay, &bytes, Phase::ContinuedCapture);
	assert_eq!(replay.pass_count(), 4);
	assert_eq!(replay.attempts().len(), 2);
	assert_eq!(replay.retirements().len(), 1);
	let prefix = replay.active_prefix_history().unwrap();
	assert_eq!(prefix.name(), b"fresh-attempt-3");
	assert_eq!(prefix.prepared().file, LinuxFileIdentity::new(7, 20));
	assert_eq!(
		prefix
			.ranges()
			.map(|range| range.length)
			.collect::<Vec<_>>(),
		vec![4]
	);
}

#[test]
fn repeated_continuation_resolves_actual_predecessor_and_keeps_one_physical_stage() {
	let run = Transcript::read(false);
	let bytes = recorded("repeated-v2");
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_clean(&replay, &bytes, Phase::WitnessIntentRequiresInspection);
	assert_eq!(replay.pass_count(), 3);
	assert_eq!(replay.attempts().len(), 1);
	assert_eq!(replay.continued_extent(), Some(length(6)));
	assert!(replay.witness().is_some());
}

#[test]
fn exact_cuts_and_bad_receipt_bindings_preserve_the_last_accepted_frame() {
	let run = Transcript::read(false);
	let valid = recorded("published");
	let bad = recorded("wrong-ready-digest");
	let rejected = scan(&run, bad.as_slice(), FRESH);
	assert_eq!(
		rejected.boundary(),
		boundary_of(&valid, FrameKind::DurabilityRecorded)
	);
	assert!(rejected.issue().is_some());
	let bad = recorded("wrong-committed-inode");
	let rejected = scan(&run, bad.as_slice(), FRESH);
	assert_eq!(
		rejected.boundary(),
		boundary_of(&valid, FrameKind::RemoteReceiptReady)
	);
	assert!(rejected.issue().is_some());
	assert!(!rejected.matches_committed_receipt(
		rejected.receipt_ready().unwrap().receipt(),
		&recorded("receipt"),
	));
	let first =
		usize::try_from(boundary_of(&valid, FrameKind::RemoteCaptureContinued).offset).unwrap();
	let mut reader = FrameReader::new(valid.as_slice(), ChainHead::start());
	let mut boundaries = Vec::new();
	while let Some(frame) = reader.next_frame().unwrap() {
		boundaries.push((usize::try_from(reader.offset()).unwrap(), frame.head()));
	}
	for count in first..valid.len() {
		let replay = scan(&run, &valid[..count], FRESH);
		let &(last, head) = boundaries.iter().rfind(|(end, _)| *end <= count).unwrap();
		assert_eq!(replay.boundary().head, head, "cut {count}");
		assert_eq!(replay.issue().is_none(), last == count, "cut {count}");
	}
}

struct ReadLimit<'source> {
	raw: &'source [u8],
	read: &'source Cell<usize>,
	limit: usize,
}

impl Read for ReadLimit<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		let offset = self.read.get();
		assert!(
			offset < self.limit,
			"unexpected impossible or oversized payload read"
		);
		let width = output.len().min(self.limit - offset);
		let count = (&self.raw[offset..]).read(&mut output[..width])?;
		self.read.set(offset + count);
		Ok(count)
	}
}

#[test]
fn profile_rejects_impossible_kind_and_oversized_payload_at_the_header() {
	let run = Transcript::read(false);
	let valid = recorded("published");
	let boundary = boundary_of(&valid, FrameKind::RemoteWitnessIntent);
	let prefix_end = usize::try_from(boundary.offset).unwrap();
	for (kind, length) in [(FrameKind::StageSealed, 544), (FrameKind::PublishIntent, 1)] {
		let mut writer = FrameWriter::new(valid[..prefix_end].to_vec(), boundary.head);
		writer.append(kind, &vec![0; length]).unwrap();
		let raw = writer.into_inner();
		let read = Cell::new(0);
		let limit = prefix_end + 56;
		let replay = scan(
			&run,
			ReadLimit {
				raw: &raw,
				read: &read,
				limit,
			},
			FRESH,
		);
		assert_eq!(replay.boundary(), boundary);
		assert!(replay.issue().is_some());
		assert_eq!(read.get(), limit);
	}
}

#[test]
fn only_available_logical_run_admits_retire_to_fresh_after_repeated_continuation() {
	let run = Transcript::read(false);
	let bytes = recorded("retire-at-63");
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_clean(&replay, &bytes, Phase::Retired);
	assert_eq!(replay.pass_count(), 63);
	assert_eq!(replay.attempts().len(), 1);
	let bytes = recorded("retire-at-64");
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_eq!(replay.pass_count(), 64);
	assert_eq!(replay.phase(), Phase::ContinuedCapture);
	assert!(replay.retirements().is_empty());
	assert!(matches!(
		replay.issue(),
		Some(RemoteReplayIssue::AttemptLimit)
	));
	assert!(replay.active_prefix_history().is_err());
}

#[test]
fn historical_consent_keeps_its_signed_deadline_without_live_clock_admission() {
	let run = Transcript::read(false);
	let bytes = recorded("archived-expired-consent");
	let replay = scan(&run, bytes.as_slice(), FRESH);
	assert_clean(&replay, &bytes, Phase::WitnessIntentRequiresInspection);
	assert_eq!(replay.witness().unwrap().consent().deadline.get(), 1);
	assert!(replay.active_prefix_history().is_err());
}

#[test]
fn terminal_commitment_refuses_trailing_frames_and_disables_receipt_association() {
	let run = Transcript::read(false);
	let bytes = recorded("published");
	let accepted = boundary_of(&bytes, FrameKind::ReceiptCommitted);
	let mut writer = FrameWriter::new(bytes, accepted.head);
	writer
		.append(FrameKind::RemoteStageAllocated, &[0])
		.unwrap();
	let replay = scan(&run, writer.into_inner().as_slice(), FRESH);
	assert_eq!(replay.phase(), Phase::ReceiptCommitted);
	assert_eq!(replay.boundary(), accepted);
	assert!(replay.issue().is_some());
	assert!(!replay.matches_committed_receipt(LinuxFileIdentity::new(7, 14), &recorded("receipt")));
}

#[test]
fn fresh_v1_archive_cannot_select_the_known_op2_digest_even_before_input_is_read() {
	let run = Transcript::read(false);
	let observed = Cell::new(0);
	let input = ReadLimit {
		raw: &[],
		read: &observed,
		limit: 0,
	};
	let result = replay_remote_witnessed_closeout(
		input,
		&run.fixture.trust(),
		&RemoteWitnessedReplaySelection {
			initial_v1_qualification: QUALIFICATION,
			fresh_v1_qualification: *run.qualification.digest().as_bytes(),
			qualification: &run.qualification,
			grant_digest: [0x72; 32],
		},
	);
	assert!(matches!(result, Err(Error::Binding)));
	assert_eq!(observed.get(), 0);
}

fn exact_clean_kind9_and_kind42_expose_distinct_receipt_views() {
	use exacopy_journal::remote_download::witness::RemoteReceiptReady;

	let run = Transcript::read(false);
	for (label, receipt_label) in [
		("published", "receipt"),
		("recovered-published", "recovered-receipt"),
	] {
		let bytes = recorded(label);
		let expected_bytes = recorded(receipt_label);
		let durable = boundary_of(&bytes, FrameKind::DurabilityRecorded);
		let ready = boundary_of(&bytes, FrameKind::RemoteReceiptReady);
		let durable_end = usize::try_from(durable.offset).unwrap();
		let ready_end = usize::try_from(ready.offset).unwrap();
		let durable_replay = scan(&run, &bytes[..durable_end], FRESH);
		let ready_replay = scan(&run, &bytes[..ready_end], FRESH);
		let basis = durable_replay.durable_receipt_basis().unwrap();
		let inspection = ready_replay.receipt_ready_inspection().unwrap();
		assert_eq!(basis.boundary(), durable);
		assert_eq!(inspection.boundary(), ready);
		assert_eq!(inspection.durability_boundary(), durable);
		assert_eq!(basis.bytes(), expected_bytes);
		assert_eq!(inspection.bytes(), expected_bytes);
		assert_eq!(usize::from(basis.length()), expected_bytes.len());
		assert_eq!(basis.length(), inspection.record().length());
		assert_eq!(basis.digest(), inspection.record().digest());
		assert_eq!(basis.witness(), inspection.witness());
		assert_eq!(basis.job_directory(), basis.witness().job_directory());
		assert_eq!(basis.job_directory(), inspection.job_directory());
		assert_eq!(basis.target_parent(), inspection.target_parent());
		assert_eq!(basis.pending_name(), inspection.pending_name());
		assert_eq!(basis.final_name(), inspection.final_name());
		assert!(basis.pending_name().starts_with(b"rw-receipt.pending."));
		assert!(basis.final_name().starts_with(b"rw-receipt.final."));
		assert!(durable_replay.receipt_ready().is_none());

		let mut frames = FrameReader::new(&bytes[durable_end..ready_end], durable.head);
		let frame = frames.next_frame().unwrap().unwrap();
		let expected = basis
			.receipt_ready_expectation(inspection.record().receipt())
			.unwrap();
		assert_eq!(expected.durability.head(), durable.head);
		assert_eq!(
			RemoteReceiptReady::encode(&expected).unwrap(),
			frame.payload()
		);
		assert!(
			basis
				.receipt_ready_expectation(basis.witness().binding().stage())
				.is_err()
		);
	}
}

fn receipt_views_refuse_every_nearby_cut_except_the_exact_clean_boundary() {
	let run = Transcript::read(false);
	let bytes = recorded("published");
	let durable =
		usize::try_from(boundary_of(&bytes, FrameKind::DurabilityRecorded).offset).unwrap();
	let ready = usize::try_from(boundary_of(&bytes, FrameKind::RemoteReceiptReady).offset).unwrap();

	for cut in durable - 1..=bytes.len() {
		let replay = scan(&run, &bytes[..cut], FRESH);
		assert_eq!(
			replay.durable_receipt_basis().is_ok(),
			cut == durable,
			"cut {cut}"
		);
		assert_eq!(
			replay.receipt_ready_inspection().is_ok(),
			cut == ready,
			"cut {cut}"
		);
	}
	for label in [
		"conflict",
		"uncertain",
		"wrong-ready-digest",
		"wrong-committed-inode",
		"retire-preserved",
	] {
		let bad = recorded(label);
		let rejected = scan(&run, bad.as_slice(), FRESH);
		assert!(rejected.durable_receipt_basis().is_err(), "{label}");
		assert!(rejected.receipt_ready_inspection().is_err(), "{label}");
	}
}

#[test]
fn receipt_basis_requires_exact_clean_phase_and_canonical_artifact() {
	exact_clean_kind9_and_kind42_expose_distinct_receipt_views();
	receipt_views_refuse_every_nearby_cut_except_the_exact_clean_boundary();
}
