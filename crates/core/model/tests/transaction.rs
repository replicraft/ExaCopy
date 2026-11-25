//! Reference-model tests for preserve-mode copy authorization and completion replay.

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngAlgorithm, RngSeed, TestCaseResult};

use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopyPhase, CopySession, EntryId, JobId, RunEpoch, StageId,
	TransitionError,
};

const HISTORY_CASES: u32 = 1_024;
const HISTORY_SEED: u64 = 0x4558_4143_434F_5059;
const MAX_HISTORY_ATTEMPTS: usize = 64;

const FIXTURE_JOB: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const OTHER_JOB: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
const FIXTURE_ENTRY: u64 = 19;
const OTHER_ENTRY: u64 = 20;
const ACTIVE_EPOCH: u64 = 2;
const OLD_EPOCH: u64 = 1;
const FIXTURE_STAGE: [u8; 16] = [0x51; 16];
const OTHER_STAGE: [u8; 16] = [0x57; 16];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sender {
	Bound,
	OtherJob,
	OtherEntry,
	OldEpoch,
	OtherStage,
}

const FOREIGN_SENDERS: [Sender; 4] = [
	Sender::OtherJob,
	Sender::OtherEntry,
	Sender::OldEpoch,
	Sender::OtherStage,
];

impl Sender {
	fn binding(self) -> CopyBinding {
		let job_bytes = if self == Self::OtherJob {
			OTHER_JOB
		} else {
			FIXTURE_JOB
		};
		let job = JobId::try_from_bytes(job_bytes).expect("fixture IDs are UUIDv7");
		let entry = if self == Self::OtherEntry {
			OTHER_ENTRY
		} else {
			FIXTURE_ENTRY
		};
		let epoch = if self == Self::OldEpoch {
			OLD_EPOCH
		} else {
			ACTIVE_EPOCH
		};
		let stage = if self == Self::OtherStage {
			OTHER_STAGE
		} else {
			FIXTURE_STAGE
		};
		CopyBinding::new(
			job,
			EntryId::new(entry),
			RunEpoch::new(epoch),
			StageId::from_bytes(stage),
		)
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorizedEffect {
	ReadSource,
	PublishNoClobber,
}

struct Milestone {
	event: CopyEvent,
	phase: CopyPhase,
	effect: Option<AuthorizedEffect>,
}

const SUCCESS_PATH: [Milestone; 10] = [
	Milestone {
		event: CopyEvent::StagePrepared,
		phase: CopyPhase::Prepared,
		effect: Some(AuthorizedEffect::ReadSource),
	},
	Milestone {
		event: CopyEvent::WritersJoined,
		phase: CopyPhase::Quiesced,
		effect: None,
	},
	Milestone {
		event: CopyEvent::DataFlushed,
		phase: CopyPhase::DataFlushed,
		effect: None,
	},
	Milestone {
		event: CopyEvent::ReadbackVerified,
		phase: CopyPhase::Verified,
		effect: None,
	},
	Milestone {
		event: CopyEvent::MetadataReady,
		phase: CopyPhase::MetadataReady,
		effect: None,
	},
	Milestone {
		event: CopyEvent::StageSealed,
		phase: CopyPhase::ReadyToPublish,
		effect: None,
	},
	Milestone {
		event: CopyEvent::PublishIntentRecorded,
		phase: CopyPhase::PublishIntent,
		effect: Some(AuthorizedEffect::PublishNoClobber),
	},
	Milestone {
		event: CopyEvent::Published,
		phase: CopyPhase::Published,
		effect: None,
	},
	Milestone {
		event: CopyEvent::DirectoryFlushed,
		phase: CopyPhase::DurabilityConfirmed,
		effect: None,
	},
	Milestone {
		event: CopyEvent::ReceiptRecorded,
		phase: CopyPhase::Receipted,
		effect: None,
	},
];

const RETAINED_STAGE_REOPENED: Milestone = Milestone {
	event: CopyEvent::RetainedStageReopened,
	phase: CopyPhase::Prepared,
	effect: None,
};

const STOP_EVENTS: [CopyEvent; 6] = [
	CopyEvent::Conflict,
	CopyEvent::OutcomeUncertain,
	CopyEvent::Cancelled,
	CopyEvent::IoFailed,
	CopyEvent::SourceChanged,
	CopyEvent::VerificationFailed,
];

#[derive(Debug, PartialEq, Eq)]
enum Decision {
	Accept(Option<AuthorizedEffect>),
	RejectBinding,
	RejectEvent { phase: CopyPhase, event: CopyEvent },
}

/// The oracle derives phase and prerequisites from an append-only record of accepted events.
#[derive(Default)]
struct AcceptedHistory {
	events: Vec<CopyEvent>,
}

impl AcceptedHistory {
	fn phase(&self) -> CopyPhase {
		self.events.last().map_or(CopyPhase::Planned, |event| {
			core::iter::once(&RETAINED_STAGE_REOPENED)
				.chain(&SUCCESS_PATH)
				.find(|milestone| milestone.event == *event)
				.map_or_else(|| stop_phase(*event), |milestone| milestone.phase)
		})
	}

	fn next_milestone(&self) -> Option<&'static Milestone> {
		if self
			.events
			.last()
			.is_some_and(|event| STOP_EVENTS.contains(event))
		{
			return None;
		}
		SUCCESS_PATH.get(self.events.len())
	}

	fn record(&mut self, sender: Sender, event: CopyEvent) -> Decision {
		if sender != Sender::Bound {
			return Decision::RejectBinding;
		}
		let Some(milestone) = self.next_milestone() else {
			return Decision::RejectEvent {
				phase: self.phase(),
				event,
			};
		};
		if self.events.is_empty() && event == RETAINED_STAGE_REOPENED.event {
			self.events.push(event);
			return Decision::Accept(RETAINED_STAGE_REOPENED.effect);
		}
		if milestone.event == event {
			self.events.push(event);
			return Decision::Accept(milestone.effect);
		}
		if self.can_stop(event) {
			self.events.push(event);
			return Decision::Accept(None);
		}
		Decision::RejectEvent {
			phase: self.phase(),
			event,
		}
	}

	fn can_stop(&self, event: CopyEvent) -> bool {
		let intent_recorded = self.events.contains(&CopyEvent::PublishIntentRecorded);
		match event {
			CopyEvent::Conflict => intent_recorded && !self.events.contains(&CopyEvent::Published),
			CopyEvent::OutcomeUncertain => intent_recorded,
			CopyEvent::Cancelled | CopyEvent::IoFailed | CopyEvent::SourceChanged => {
				!intent_recorded
			}
			CopyEvent::VerificationFailed => self.events.last() == Some(&CopyEvent::DataFlushed),
			_ => false,
		}
	}
}

fn stop_phase(event: CopyEvent) -> CopyPhase {
	match event {
		CopyEvent::Conflict => CopyPhase::Conflict,
		CopyEvent::OutcomeUncertain => CopyPhase::RecoveryRequired,
		CopyEvent::Cancelled => CopyPhase::Cancelled,
		CopyEvent::IoFailed => CopyPhase::IoFailed,
		CopyEvent::SourceChanged => CopyPhase::SourceChanged,
		CopyEvent::VerificationFailed => CopyPhase::VerificationFailed,
		_ => panic!("reference fixture has no phase for {event:?}"),
	}
}

struct Comparison {
	session: CopySession,
	history: AcceptedHistory,
}

impl Comparison {
	fn with_prefix(prefix: &[Milestone]) -> Result<Self, TestCaseError> {
		let mut comparison = Self {
			session: CopySession::new(Sender::Bound.binding()),
			history: AcceptedHistory::default(),
		};
		prop_assert_eq!(comparison.session.phase(), CopyPhase::Planned);
		for milestone in prefix {
			comparison.check(Sender::Bound, milestone.event)?;
		}
		Ok(comparison)
	}

	fn check(&mut self, sender: Sender, event: CopyEvent) -> TestCaseResult {
		let before = self.history.phase();
		let expected = self.history.record(sender, event);
		let actual = match self.session.apply(sender.binding(), event) {
			Ok(None) => Decision::Accept(None),
			Ok(Some(effect)) => {
				let (kind, binding) = match effect {
					CopyEffect::ReadSource(permit) => {
						(AuthorizedEffect::ReadSource, permit.binding())
					}
					CopyEffect::PublishNoClobber(permit) => {
						(AuthorizedEffect::PublishNoClobber, permit.binding())
					}
				};
				prop_assert_eq!(
					binding,
					Sender::Bound.binding(),
					"effect {:?} at {:?} for {:?}",
					kind,
					before,
					event
				);
				Decision::Accept(Some(kind))
			}
			Err(TransitionError::MismatchedBinding) => Decision::RejectBinding,
			Err(TransitionError::InvalidEvent { phase, event }) => {
				Decision::RejectEvent { phase, event }
			}
		};
		prop_assert_eq!(
			actual,
			expected,
			"phase {:?}, sender {:?}, event {:?}",
			before,
			sender,
			event
		);
		prop_assert_eq!(
			self.session.phase(),
			self.history.phase(),
			"after {:?} from {:?}",
			event,
			sender
		);
		Ok(())
	}
}

fn all_events() -> impl Iterator<Item = CopyEvent> + Clone {
	SUCCESS_PATH
		.iter()
		.map(|milestone| milestone.event)
		.chain([RETAINED_STAGE_REOPENED.event])
		.chain(STOP_EVENTS)
}

#[derive(Clone, Copy, Debug)]
enum Attempt {
	Send { sender: Sender, event: CopyEvent },
	Advance,
	Replay { sender: Sender },
}

fn attempts() -> impl Strategy<Value = Attempt> {
	let sender = || prop_oneof![4 => Just(Sender::Bound), 1 => proptest::sample::select(&FOREIGN_SENDERS[..])];
	prop_oneof![
		4 => (sender(), proptest::sample::select(all_events().collect::<Vec<_>>()))
			.prop_map(|(sender, event)| Attempt::Send { sender, event }),
		3 => Just(Attempt::Advance),
		2 => sender().prop_map(|sender| Attempt::Replay { sender }),
	]
}

proptest! {
	#![proptest_config(ProptestConfig {
		cases: HISTORY_CASES,
		rng_algorithm: RngAlgorithm::ChaCha,
		rng_seed: RngSeed::Fixed(HISTORY_SEED),
		failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
		..ProptestConfig::default()
	})]

	#[test]
	fn generated_copy_histories_agree_with_the_reference_ledger(
		prefix_len in 0..=SUCCESS_PATH.len(),
		attempts in proptest::collection::vec(attempts(), 1..=MAX_HISTORY_ATTEMPTS),
	) {
		let mut comparison = Comparison::with_prefix(&SUCCESS_PATH[..prefix_len])?;
		for attempt in attempts {
			let (sender, event) = match attempt {
				Attempt::Send { sender, event } => (sender, event),
				Attempt::Advance => {
					let event = comparison.history.next_milestone()
						.map_or(CopyEvent::ReceiptRecorded, |milestone| milestone.event);
					(Sender::Bound, event)
				}
				Attempt::Replay { sender } => {
					let event = comparison.history.events.last().copied().unwrap_or(CopyEvent::WritersJoined);
					(sender, event)
				}
			};
			comparison.check(sender, event)?;
		}
	}
}

#[test]
fn every_phase_checks_event_order_stop_rules_and_completion_binding() -> TestCaseResult {
	for prefix_len in 0..=SUCCESS_PATH.len() {
		for event in all_events() {
			let mut comparison = Comparison::with_prefix(&SUCCESS_PATH[..prefix_len])?;
			for sender in FOREIGN_SENDERS {
				comparison.check(sender, event)?;
			}
			comparison.check(Sender::Bound, event)?;
			if comparison.history.next_milestone().is_none() {
				for late_event in all_events() {
					comparison.check(Sender::Bound, late_event)?;
				}
			}
		}
	}
	Ok(())
}

#[test]
fn repeated_prepare_and_publish_intent_cannot_authorize_a_second_effect() -> TestCaseResult {
	let mut comparison = Comparison::with_prefix(&[])?;
	for milestone in &SUCCESS_PATH {
		comparison.check(Sender::Bound, milestone.event)?;
		if milestone.effect.is_some() {
			comparison.check(Sender::Bound, milestone.event)?;
			for sender in FOREIGN_SENDERS {
				comparison.check(sender, milestone.event)?;
			}
		}
	}
	Ok(())
}

#[test]
fn tlc_early_publication_counterexample_stops_before_namespace_effect() {
	// Project the TLC mutant trace Init → Prepare → StartAttempt → ApplyNoClobber.
	let binding = Sender::Bound.binding();
	let mut session = CopySession::new(binding);
	assert!(matches!(
		session.apply(binding, CopyEvent::StagePrepared),
		Ok(Some(CopyEffect::ReadSource(_)))
	));
	assert_eq!(
		session.apply(binding, CopyEvent::PublishIntentRecorded),
		Err(TransitionError::InvalidEvent {
			phase: CopyPhase::Prepared,
			event: CopyEvent::PublishIntentRecorded,
		}),
	);
	assert_eq!(session.phase(), CopyPhase::Prepared);
}

#[test]
fn retained_stage_retry_rejects_old_evidence_and_authorizes_one_fresh_effect() {
	let old_binding = Sender::OldEpoch.binding();
	let binding = Sender::Bound.binding();
	let mut session = CopySession::new(binding);
	assert_eq!(
		session.apply(binding, CopyEvent::RetainedStageReopened),
		Ok(None)
	);

	for milestone in SUCCESS_PATH[1..]
		.iter()
		.take_while(|milestone| milestone.event != CopyEvent::PublishIntentRecorded)
	{
		let phase = session.phase();
		assert_eq!(
			session.apply(binding, CopyEvent::PublishIntentRecorded),
			Err(TransitionError::InvalidEvent {
				phase,
				event: CopyEvent::PublishIntentRecorded,
			})
		);
		assert_eq!(
			session.apply(old_binding, milestone.event),
			Err(TransitionError::MismatchedBinding)
		);
		assert_eq!(session.apply(binding, milestone.event), Ok(None));
		assert_eq!(session.phase(), milestone.phase);
	}

	let event = CopyEvent::PublishIntentRecorded;
	assert_eq!(
		session.apply(old_binding, event),
		Err(TransitionError::MismatchedBinding)
	);
	assert!(matches!(
		session.apply(binding, event),
		Ok(Some(CopyEffect::PublishNoClobber(permit))) if permit.binding() == binding
	));
	assert_eq!(
		session.apply(binding, event),
		Err(TransitionError::InvalidEvent {
			phase: CopyPhase::PublishIntent,
			event,
		})
	);
}
