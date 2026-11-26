use exacopy_journal::remote_download::witness::records::{
	RemoteRetainedWitness, RemoteWitnessCloseoutBody as Body,
	RemoteWitnessCloseoutRecord as Record, RemoteWitnessedOutcome,
};

use super::*;

fn phase_vector(label: &str) -> Vec<u8> {
	include_str!("witness_phase_records.hex")
		.lines()
		.find_map(|line| {
			let (name, bytes) = line.split_once(' ')?;
			(name == label).then(|| hex(bytes))
		})
		.unwrap()
}

#[test]
fn exact_witnessed_phase_transcript_round_trips_and_legacy_refuses() {
	let run = Transcript::read(false);
	let binding = run.receipt().witness.binding();
	for pair in run.frames[1..].windows(2) {
		let previous = pair[0].1;
		let (frame, end) = &pair[1];
		let record = Record::from_frame(frame, *end, binding, previous).unwrap();
		assert_eq!(record.body().kind(), frame.kind());
		assert_eq!(record.encode().unwrap(), frame.payload());
		assert!(RemoteFinalizationRecord::from_frame(frame).is_err());
		for cut in 0..frame.payload().len() {
			let payload = &frame.payload()[..cut];
			let (frame, end) = append(previous, frame.kind(), payload);
			assert!(Record::from_frame(&frame, end, binding, previous).is_err());
		}
		let cap = Record::payload_cap(frame.kind()).unwrap();
		let (frame, end) = append(previous, frame.kind(), &vec![0; cap + 1]);
		assert_eq!(
			Record::from_frame(&frame, end, binding, previous),
			Err(Error::Length)
		);
	}
}

#[test]
fn independent_terminal_and_retirement_declarations_keep_exact_variants() {
	let run = Transcript::read(false);
	let receipt = run.receipt();
	let binding = receipt.witness.binding();
	let parse = |label, kind, previous| {
		let payload = phase_vector(label);
		let (frame, end) = append(previous, kind, &payload);
		let record = Record::from_frame(&frame, end, binding, previous).unwrap();
		assert_eq!(record.encode().unwrap(), payload, "{label}");
		if kind == FrameKind::RemoteCaptureRetired {
			assert!(
				exacopy_journal::remote_download::retirement::RemoteCaptureRetired::from_frame(
					&frame
				)
				.is_err(),
			);
		} else {
			assert!(RemoteFinalizationRecord::from_frame(&frame).is_err());
		}
	};
	for label in [
		"observation-conflict",
		"observation-uncertain",
		"observation-recovered",
	] {
		parse(label, FrameKind::PublishObserved, run.frames[5].1);
	}
	for (label, index) in [
		("retire-unwitnessed", 0),
		("retire-absent-at-intent", 1),
		("retire-preserved", 4),
	] {
		parse(label, FrameKind::RemoteCaptureRetired, run.frames[index].1);
	}
	let previous = RemoteReplayBoundary {
		head: ChainHead::after(receipt.boundary.head.sequence() + 1, [0x9b; 32]).unwrap(),
		offset: receipt.boundary.offset + 512,
	};
	parse("commit-fixture-head", FrameKind::ReceiptCommitted, previous);

	let previous = run.frames[5].1;
	let (frame, end) = append(
		previous,
		FrameKind::PublishObserved,
		&phase_vector("observation-conflict"),
	);
	assert!(matches!(
		Record::from_frame(&frame, end, binding, previous)
			.unwrap()
			.body(),
		Body::Observed(RemoteWitnessedOutcome::Conflict)
	));
	let previous = run.frames[1].1;
	let (frame, end) = append(
		previous,
		FrameKind::RemoteCaptureRetired,
		&phase_vector("retire-absent-at-intent"),
	);
	assert!(matches!(
		Record::from_frame(&frame, end, binding, previous).unwrap().body(),
		Body::Retire { retained: RemoteRetainedWitness::AbsentAfterIntent(head), .. } if head == previous.head
	));
}
