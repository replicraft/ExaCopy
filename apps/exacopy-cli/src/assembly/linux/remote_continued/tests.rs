use std::io::Read as _;
use std::num::NonZeroU16;

use ed25519_dalek::SigningKey;
use exacopy_journal::frame::{ChainHead, FRAME_OVERHEAD_BYTES, FrameKind, FrameReader};
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	verify_remote_witness_qualification,
};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationRouteClass, RemoteQualificationScope,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::WitnessedPassBudget;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedReplaySelection, replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, RemoteBootstrapTrust, RemoteDownloadOwnerRecord,
};
use exacopy_journal::{OwnerProfileId, StreamDigest, StreamLength};

use super::activation::{AdmissionError, confirm_selected, model_head, reservation_plan};
use super::checkpoints::{CheckpointPass, checkpoint_range_at};
use exacopy_journal::remote_download::continuation::checkpoint::{
	RemoteContinuedCheckpoint, RemoteContinuedRange,
};

macro_rules! vector {
	($file:literal) => {
		include_str!(concat!(
			env!("CARGO_MANIFEST_DIR"),
			"/../../crates/storage/exacopy-journal/tests/",
			$file
		))
	};
}

fn hex(encoded: &str) -> Vec<u8> {
	let digits: Vec<_> = encoded.bytes().filter(u8::is_ascii_hexdigit).collect();
	let (pairs, rest) = digits.as_chunks::<2>();
	assert!(rest.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn field(vector: &str, label: &str) -> Vec<u8> {
	hex(vector
		.lines()
		.find_map(|row| row.strip_prefix(label)?.strip_prefix(' '))
		.unwrap())
}

#[test]
fn actual_signed_kind40_must_form_the_exact_clean_successor() {
	let profile = OwnerProfileId::from_bytes([0x22; 16]).unwrap();
	let owner_key = SigningKey::from_bytes(&[0x52; 32]).verifying_key();
	let owner = RemoteDownloadOwnerRecord::decode(
		&hex(vector!("remote_finalization/owner.hex")),
		profile,
		&owner_key,
	)
	.unwrap();
	let trust = RemoteBootstrapTrust::new(&owner, profile, &owner_key).unwrap();
	let attestor = SigningKey::from_bytes(&[0x62; 32]).verifying_key();
	let qualification = verify_remote_witness_qualification(
		&field(
			vector!("remote_continuation/witness_closeout.hex"),
			"qualification",
		),
		&RemoteContinuationQualificationTrust {
			attestor: [0x31; 16],
			attestor_key: &attestor,
			owner_key: &owner_key,
			scope: RemoteContinuationQualificationScope {
				common: RemoteQualificationScope {
					build: [0x61; 32],
					route: RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1,
					campaign_scope: [0x63; 32],
					campaign_evidence: [0x64; 32],
				},
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
				coverage:
					RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
			},
		},
	)
	.unwrap();
	let selection = RemoteWitnessedReplaySelection {
		initial_v1_qualification: [0x71; 32],
		fresh_v1_qualification: [0x85; 32],
		qualification: &qualification,
		grant_digest: [0x72; 32],
	};
	let full = field(
		vector!("remote_continuation/witnessed_replay.hex"),
		"published",
	);
	check_exact_live_witness_vector(&full, &trust, &selection);
	let mut cursor = FrameReader::new(full.as_slice(), ChainHead::start());
	let mut previous = 0;
	let mut previous_head = ChainHead::start();
	let next = loop {
		let frame = cursor.next_frame().unwrap().unwrap();
		if frame.kind() == FrameKind::RemoteCaptureContinued {
			break RemoteReplayBoundary {
				head: frame.head(),
				offset: cursor.offset(),
			};
		}
		previous = usize::try_from(cursor.offset()).unwrap();
		previous_head = frame.head();
	};
	let prior = RemoteReplayBoundary {
		head: previous_head,
		offset: previous as u64,
	};
	let end = usize::try_from(next.offset).unwrap();
	let mut proposed = full[previous..end].to_vec();
	let physical = &full[..previous];
	confirm_selected::<()>(
		physical.chain(proposed.as_slice()),
		&trust,
		&selection,
		next,
	)
	.unwrap();
	confirm_selected::<()>(&full[..end], &trust, &selection, next).unwrap();
	assert!(matches!(
		confirm_selected::<()>(&full[..end - 1], &trust, &selection, next),
		Err(AdmissionError::Binding)
	));
	assert!(matches!(
		confirm_selected::<()>(full.as_slice(), &trust, &selection, next),
		Err(AdmissionError::Binding)
	));
	let signed_region = proposed.len() / 2;
	proposed[signed_region] ^= 1;
	assert!(matches!(
		confirm_selected::<()>(
			physical.chain(proposed.as_slice()),
			&trust,
			&selection,
			next
		),
		Err(AdmissionError::Binding)
	));

	let tail = field(
		vector!("remote_continuation/witness_closeout.hex"),
		"tail-prefix",
	);
	let mut transcript = physical.to_vec();
	transcript.extend_from_slice(&tail);
	let zero_scan = replay_remote_witnessed_closeout(&full[..end], &trust, &selection).unwrap();
	let zero_history = zero_scan.active_prefix_history().unwrap();
	let zero_plan = WitnessedPassBudget::plan(
		prior,
		StreamLength::new(zero_history.covered_extent()).unwrap(),
		zero_history.source().length(),
		NonZeroU16::MIN,
	)
	.unwrap();
	assert_eq!(zero_plan.checkpoint_count(), 0);
	assert!(reservation_plan(zero_plan).unwrap().reserve_end() > next.offset);

	let mut framed = FrameReader::new(transcript.as_slice(), ChainHead::start());
	let mut lineage = None;
	let mut accepted_checkpoints = 0;
	while let Some(frame) = framed.next_frame().unwrap() {
		let boundary = RemoteReplayBoundary {
			head: frame.head(),
			offset: framed.offset(),
		};
		if frame.kind() == FrameKind::RemoteCaptureContinued {
			lineage = Some(model_head(boundary));
			let selected = &transcript[..usize::try_from(boundary.offset).unwrap()];
			let witnessed = replay_remote_witnessed_closeout(selected, &trust, &selection).unwrap();
			let history = witnessed.active_prefix_history().unwrap();
			let plan = WitnessedPassBudget::plan(
				prior,
				StreamLength::new(history.covered_extent()).unwrap(),
				history.source().length(),
				NonZeroU16::MIN,
			)
			.unwrap();
			let range = plan.checkpoint_range(NonZeroU16::MIN).unwrap();
			let probe = RemoteContinuedCheckpoint::new(
				history.context(),
				boundary.head,
				boundary.head,
				history.epochs(),
				RemoteContinuedRange {
					ordinal: 1,
					offset: range.start,
					length: range.end - range.start,
					digest: StreamDigest::from_bytes([0; 32]),
				},
			)
			.unwrap()
			.encode()
			.unwrap();
			let end = boundary.offset + (FRAME_OVERHEAD_BYTES + probe.len()) as u64;
			let remaining = plan
				.required_after_checkpoint(boundary, NonZeroU16::MIN, end)
				.unwrap();
			let native = reservation_plan(plan).unwrap();
			assert_eq!(native.accepted(), model_head(prior));
			assert!(native.reserve_end() >= end + remaining.journal_bytes());
			assert!(remaining.receipt_bytes() > 0);
		} else if let Some(lineage) = lineage
			&& frame.kind() == FrameKind::RangeCheckpoint
		{
			let checkpoint = RemoteContinuedCheckpoint::from_frame(&frame).unwrap();
			let range = checkpoint.range();
			let pass = CheckpointPass {
				trust: &trust,
				selection: &selection,
				context: checkpoint.context(),
				epochs: checkpoint.epochs(),
				lineage,
			};
			let end = range.offset + range.length;
			let checkpoint_bytes = &transcript[..usize::try_from(boundary.offset).unwrap()];
			pass.confirm_range::<()>(checkpoint_bytes, boundary, end)
				.unwrap();
			assert!(
				pass.confirm_range::<()>(checkpoint_bytes, boundary, end + 1)
					.is_err()
			);
			assert!(
				pass.confirm_range::<()>(
					&checkpoint_bytes[..checkpoint_bytes.len() - 1],
					boundary,
					end
				)
				.is_err()
			);
			accepted_checkpoints += 1;
		}
	}
	assert!(accepted_checkpoints > 0);
}

#[test]
fn planned_checkpoint_refuses_a_displaced_or_stopped_source_cursor() {
	let adopted = 7;
	let first_end = adopted + MAX_REMOTE_CHECKPOINT_BYTES;
	let boundary = RemoteReplayBoundary {
		head: ChainHead::after(1, [0x32; 32]).unwrap(),
		offset: FRAME_OVERHEAD_BYTES as u64,
	};
	let first = NonZeroU16::MIN;
	let plan = WitnessedPassBudget::plan(
		boundary,
		StreamLength::new(adopted).unwrap(),
		StreamLength::new(first_end + 1).unwrap(),
		first,
	)
	.unwrap();
	assert_eq!(plan.checkpoint_count(), 2);
	assert_eq!(
		checkpoint_range_at(plan, first, adopted, Some(adopted)),
		Some(adopted..first_end)
	);
	assert!(checkpoint_range_at(plan, first, adopted, Some(adopted + 1)).is_none());
	assert!(checkpoint_range_at(plan, first, adopted, None).is_none());
}
fn check_exact_live_witness_vector(
	full: &[u8],
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) {
	use super::witness::confirm_intent;
	use exacopy_journal::remote_download::witness::RemoteWitnessIntentExpectation;

	let mut framed = FrameReader::new(full, ChainHead::start());
	let (prior, end, frame) = loop {
		let before = framed.offset() as usize;
		let frame = framed.next_frame().unwrap().unwrap();
		if frame.kind() == FrameKind::RemoteWitnessIntent {
			break (before, framed.offset() as usize, frame);
		}
	};
	let complete = replay_remote_witnessed_closeout(&full[..end], trust, selection).unwrap();
	let recorded = complete.witness().unwrap();
	assert_eq!(
		confirm_intent(&complete, recorded).unwrap(),
		recorded.witness_name()
	);
	let prior = replay_remote_witnessed_closeout(&full[..prior], trust, selection).unwrap();
	assert!(confirm_intent(&prior, recorded).is_err());
	let coverage = prior.complete_coverage_predecessor().unwrap();
	let expected = RemoteWitnessIntentExpectation {
		coverage,
		qualification: selection.qualification,
		stage_directory: prior.active_prefix_history().unwrap().prepared().directory,
		job_directory: recorded.job_directory(),
		consent: recorded.consent(),
	};
	let signed = trust
		.sign_witness_intent(&expected, &SigningKey::from_bytes(&[0x52; 32]))
		.unwrap();
	assert_eq!(signed, frame.payload());
	assert!(
		confirm_intent(
			&replay_remote_witnessed_closeout(&full[..end - 1], trust, selection).unwrap(),
			recorded
		)
		.is_err()
	);
	assert!(
		confirm_intent(
			&replay_remote_witnessed_closeout(full, trust, selection).unwrap(),
			recorded
		)
		.is_err()
	);
}

mod hosted_witness;
