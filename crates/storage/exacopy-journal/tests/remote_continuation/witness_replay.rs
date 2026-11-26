use super::*;

use exacopy_endpoint::UnixComponent;
use exacopy_journal::StreamLength;
use exacopy_journal::remote_download::RemoteSourceObservation;
use exacopy_journal::remote_download::continuation::replay::{
	RemoteWitnessContinuationReplay, RemoteWitnessContinuationSelection,
	replay_remote_witness_continuation,
};
use exacopy_journal::remote_download::continuation::{
	CoverageBasis, PriorPreparation, RemoteContinuationClaims, RemoteContinuationCoverage,
	RemoteContinuationExpectation, RemoteContinuationPrior,
};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, replay_remote_finalization_with_checkpoints,
};
use exacopy_journal::remote_download::qualification::continuation::{
	VerifiedRemoteWitnessQualification, verify_remote_witness_qualification,
};

fn witness_qualification(
	label: &str,
	route: Route,
	owner: &VerifyingKey,
) -> VerifiedRemoteWitnessQualification {
	let record = include_str!("witness_replay_qualification.hex")
		.lines()
		.filter_map(|line| line.split_once(' '))
		.find_map(|(case, bytes)| (case == label).then_some(bytes))
		.unwrap();
	let attestor = SigningKey::from_bytes(&[0x62; 32]).verifying_key();
	verify_remote_witness_qualification(
		&hex(record),
		&RemoteContinuationQualificationTrust {
			attestor: [0x31; 16],
			attestor_key: &attestor,
			owner_key: owner,
			scope: RemoteContinuationQualificationScope {
				common: RemoteQualificationScope {
					build: [0x61; 32],
					route,
					campaign_scope: [0x63; 32],
					campaign_evidence: [0x64; 32],
				},
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
				coverage:
					RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
			},
		},
	)
	.unwrap()
}

fn selection(
	qualification: &VerifiedRemoteWitnessQualification,
) -> RemoteWitnessContinuationSelection<'_> {
	RemoteWitnessContinuationSelection {
		initial_v1_qualification: LEGACY_QUALIFICATION,
		qualification,
		grant_digest: GRANT,
	}
}

fn append_continuation(
	fixture: &Fixture,
	prefix: &[u8],
	digest: [u8; 32],
	grant: [u8; 32],
) -> (Vec<u8>, RemoteReplayBoundary) {
	let trust = fixture.trust();
	let prior =
		replay_remote_finalization_with_checkpoints(prefix, &trust, LEGACY_QUALIFICATION, None)
			.unwrap();
	let inventory = prior.active_checkpoints().unwrap();
	let prepared = inventory.prepared();
	let row = inventory.checkpoints().last().unwrap();
	let old = inventory.epochs();
	let epochs = RemoteEpochs {
		run: old.run.checked_add(1).unwrap(),
		source: old.source.checked_add(1).unwrap(),
	};
	let claims = RemoteContinuationClaims {
		context: inventory.context(),
		scope: inventory.scope().unwrap(),
		previous: inventory.boundary(),
		prior: RemoteContinuationPrior {
			bootstrap: prior.stage_directory_prepared().unwrap().head(),
			allocation: inventory.allocation(),
			prepared: prepared.head,
			active: PriorPreparation::Original(prepared.head),
			epochs: old,
			name: UnixComponent::new(inventory.name()).unwrap(),
			nonce: *inventory.nonce(),
		},
		directory: prepared.directory,
		stage: prepared.file,
		coverage: RemoteContinuationCoverage {
			basis: CoverageBasis::Checkpoint {
				head: row.head(),
				ordinal: row.ordinal(),
			},
			end: StreamLength::new(inventory.covered_extent()).unwrap(),
		},
		epochs,
		source: RemoteSourceObservation::new(StreamLength::new(7).unwrap(), 0o100600, 23).unwrap(),
		adopted_end: StreamLength::new(4).unwrap(),
		prefix_digest: StreamDigest::from_bytes(*blake3::hash(b"ABCD").as_bytes()),
		grant_digest: grant,
		qualification_digest: digest,
	};
	let payload = trust
		.sign_continuation(
			&RemoteContinuationExpectation {
				claims,
				prior_source_extent: inventory.source().length(),
			},
			&SigningKey::from_bytes(&[0x52; 32]),
		)
		.unwrap();
	let mut writer = FrameWriter::new(prefix.to_vec(), inventory.boundary().head);
	let continued = writer
		.append(FrameKind::RemoteCaptureContinued, &payload)
		.unwrap();
	let boundary = RemoteReplayBoundary {
		head: continued,
		offset: inventory.boundary().offset
			+ u64::try_from(FRAME_OVERHEAD_BYTES + payload.len()).unwrap(),
	};
	let checkpoint = RemoteContinuedCheckpoint::new(
		claims.context,
		continued,
		continued,
		epochs,
		RemoteContinuedRange {
			ordinal: 1,
			offset: 4,
			length: 3,
			digest: StreamDigest::from_bytes(*blake3::hash(b"EFG").as_bytes()),
		},
	)
	.unwrap();
	writer
		.append(FrameKind::RangeCheckpoint, &checkpoint.encode().unwrap())
		.unwrap();
	(writer.into_inner(), boundary)
}

#[test]
fn independently_selected_witness_replay_refuses_other_profiles_and_keeps_exact_boundary() {
	let fixture = Fixture::new();
	let qualification =
		witness_qualification("embedded", Route::EmbeddedWireGuardTcpV1, &fixture.key);
	let selected = selection(&qualification);
	let prefix = fixture.bytes_through(5);
	let prior = replay_remote_witness_continuation(prefix, &fixture.trust(), &selected).unwrap();
	assert!(matches!(
		prior.history().state(),
		RemoteContinuationState::Legacy(RemoteFinalizationPhase::Capture)
	));
	let (bytes, continued) =
		append_continuation(&fixture, prefix, *qualification.digest().as_bytes(), GRANT);
	let scan =
		replay_remote_witness_continuation(bytes.as_slice(), &fixture.trust(), &selected).unwrap();
	let history = scan.history();
	let RemoteContinuationState::Continued(active) = history.state() else {
		panic!(
			"expected clean witnessed history, got {:?}",
			history.state()
		);
	};
	assert_eq!(active.admitted_at(), continued);
	assert_eq!(active.covered_end(), 7);
	assert_eq!(active.checkpoints().len(), 1);
	let evidence = history.active_prefix_history().unwrap();
	assert_eq!(
		evidence.expected_qualification(),
		*qualification.digest().as_bytes()
	);
	assert_eq!(evidence.recorded_grant(), Some(GRANT));

	let old = fixture.replay(bytes.as_slice());
	assert!(matches!(
		old.state(),
		RemoteContinuationState::ReconciliationRequired(_)
	));
	assert_eq!(old.boundary(), fixture.boundary(5));

	for bytes in [
		fixture.bytes.as_slice(),
		append_continuation(
			&fixture,
			prefix,
			*qualification.digest().as_bytes(),
			[0x31; 32],
		)
		.0
		.as_slice(),
	] {
		let wrong = replay_remote_witness_continuation(bytes, &fixture.trust(), &selected).unwrap();
		assert_eq!(wrong.history().boundary(), fixture.boundary(5));
		assert!(matches!(
			wrong.history().state(),
			RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::Record {
				problem: RemoteReplayMismatch::Payload(Error::Binding),
				..
			})
		));
	}
}

#[test]
fn witnessed_selection_rejects_wrong_owner_route_or_grant_before_reading() {
	struct NoRead;
	impl Read for NoRead {
		fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
			panic!("invalid independent selection read input")
		}
	}
	let fixture = Fixture::new();
	let other_owner = SigningKey::from_bytes(&[0x53; 32]).verifying_key();
	let wrong_owner =
		witness_qualification("embedded", Route::EmbeddedWireGuardTcpV1, &other_owner);
	let wrong_route = witness_qualification("direct", Route::DirectPinnedTcpV1, &fixture.key);
	let wrong_parent =
		witness_qualification("wrong-parent", Route::EmbeddedWireGuardTcpV1, &fixture.key);
	let right = witness_qualification("embedded", Route::EmbeddedWireGuardTcpV1, &fixture.key);
	for selected in [
		selection(&wrong_owner),
		selection(&wrong_route),
		selection(&wrong_parent),
		RemoteWitnessContinuationSelection {
			grant_digest: [0; 32],
			..selection(&right)
		},
		RemoteWitnessContinuationSelection {
			initial_v1_qualification: *right.digest().as_bytes(),
			..selection(&right)
		},
	] {
		assert!(matches!(
			replay_remote_witness_continuation(NoRead, &fixture.trust(), &selected),
			Err(Error::Binding)
		));
	}
}

#[test]
fn witnessed_replay_requires_consecutive_frames_and_refuses_unselected_closeout() {
	let fixture = Fixture::new();
	let qualification =
		witness_qualification("embedded", Route::EmbeddedWireGuardTcpV1, &fixture.key);
	let selected = selection(&qualification);
	let previous = fixture.boundary(4);
	let skipped = ChainHead::after(previous.head.sequence() + 1, previous.head.digest()).unwrap();
	let mut writer = FrameWriter::new(fixture.bytes_through(4).to_vec(), skipped);
	writer
		.append(FrameKind::RangeCheckpoint, fixture.frames[4].0.payload())
		.unwrap();
	let gap = replay_remote_witness_continuation(
		writer.into_inner().as_slice(),
		&fixture.trust(),
		&selected,
	)
	.unwrap();
	assert_eq!(gap.history().boundary(), previous);
	assert!(matches!(
		gap.history().state(),
		RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::Framing(
			FrameReadError::Corrupt {
				problem: FrameProblem::Sequence(6),
				..
			}
		))
	));

	let (bytes, continued) = append_continuation(
		&fixture,
		fixture.bytes_through(5),
		*qualification.digest().as_bytes(),
		GRANT,
	);
	let read = |input: &[u8]| -> RemoteWitnessContinuationReplay {
		replay_remote_witness_continuation(input, &fixture.trust(), &selected).unwrap()
	};
	let accepted = read(&bytes).history().boundary();
	let mut extra = FrameWriter::new(bytes, accepted.head);
	extra
		.append(FrameKind::StageSealed, b"unsupported")
		.unwrap();
	struct HeaderOnly<'bytes>(&'bytes [u8]);
	impl Read for HeaderOnly<'_> {
		fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
			assert!(!self.0.is_empty(), "unsupported frame payload was read");
			self.0.read(output)
		}
	}
	let extra = extra.into_inner();
	let payload_start = usize::try_from(accepted.offset).unwrap() + FRAME_OVERHEAD_BYTES - 36;
	let refused = replay_remote_witness_continuation(
		HeaderOnly(&extra[..payload_start]),
		&fixture.trust(),
		&selected,
	)
	.unwrap();
	assert_eq!(refused.history().boundary(), accepted);
	assert!(matches!(
		refused.history().state(),
		RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::Record {
			problem: RemoteReplayMismatch::UnsupportedKind,
			..
		})
	));
	assert!(continued.offset < accepted.offset);
}

fn prefix_with_attempts(fixture: &Fixture, count: u8) -> Vec<u8> {
	let scan = fixture.replay(fixture.bytes_through(5));
	let old = &scan.attempts()[0];
	let stage = old.prepared().unwrap();
	let context = RemoteDownloadRecord::from_frame(&fixture.frames[2].0)
		.unwrap()
		.context();
	let mut writer = FrameWriter::new(fixture.bytes_through(2).to_vec(), fixture.boundary(2).head);
	let mut previous = None;
	for run in 1..=count {
		let epochs = RemoteEpochs {
			run: NonZeroU64::new(u64::from(run)).unwrap(),
			source: NonZeroU64::new(u64::from(run) + 10).unwrap(),
		};
		let name = format!("bounded-attempt-{run}");
		let nonce = [run; 16];
		let allocation = RemoteDownloadRecord::new(
			context,
			Some(writer.head()),
			RemoteDownloadBody::StageAllocated {
				previous,
				next: epochs,
				name: UnixComponent::new(name.as_bytes()).unwrap(),
				nonce,
				source: old.source(),
			},
		)
		.unwrap()
		.encode()
		.unwrap();
		let allocated = writer
			.append(FrameKind::RemoteStageAllocated, &allocation)
			.unwrap();
		previous = Some(epochs);
		if run != count {
			continue;
		}
		let prepared = RemoteDownloadRecord::new(
			context,
			Some(allocated),
			RemoteDownloadBody::EntryPrepared {
				allocation: allocated,
				epochs,
				nonce,
				stage_directory: stage.directory,
				stage: stage.file,
			},
		)
		.unwrap()
		.encode()
		.unwrap();
		let prepared = writer.append(FrameKind::EntryPrepared, &prepared).unwrap();
		let checkpoint = RemoteDownloadRecord::new(
			context,
			Some(prepared),
			RemoteDownloadBody::RangeCheckpoint {
				prepared,
				epochs,
				ordinal: 1,
				offset: 0,
				length: 2,
				digest: StreamDigest::from_bytes(*blake3::hash(b"AB").as_bytes()),
			},
		)
		.unwrap()
		.encode()
		.unwrap();
		writer
			.append(FrameKind::RangeCheckpoint, &checkpoint)
			.unwrap();
	}
	writer.into_inner()
}

#[test]
fn witnessed_continuation_consumes_one_jobwise_pass_slot() {
	let fixture = Fixture::new();
	let qualification =
		witness_qualification("embedded", Route::EmbeddedWireGuardTcpV1, &fixture.key);
	let selected = selection(&qualification);
	for count in [63, 64] {
		let prefix = prefix_with_attempts(&fixture, count);
		let (bytes, _) =
			append_continuation(&fixture, &prefix, *qualification.digest().as_bytes(), GRANT);
		let result =
			replay_remote_witness_continuation(bytes.as_slice(), &fixture.trust(), &selected)
				.unwrap();
		assert_eq!(result.history().attempts().len(), usize::from(count));
		let state = result.history().state();
		if count == 63 {
			assert!(matches!(
				state,
				RemoteContinuationState::Continued(active) if active.epochs().run.get() == 64
			));
		} else {
			assert!(matches!(
				state,
				RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::AttemptLimit)
			));
			assert_eq!(
				result.history().boundary().offset,
				u64::try_from(prefix.len()).unwrap()
			);
		}
	}
}
