//! Bounded preserve-mode histories using the executable model and simulated storage.

#[path = "preservation/fixture.rs"]
mod fixture;

use exacopy_endpoint::UnixComponent;
use exacopy_model::CopyPhase;
use exacopy_testkit::{Area, EffectError, EffectFault, EffectOperation, Entry, Failure};

use fixture::{Boundary, CONTENTS, Case, Fixture, INCUMBENT, REBOUND, Race, Script};

struct Expected {
	phase: CopyPhase,
	live_target: bool,
	stable_target: bool,
	stable_stage: bool,
	intent: bool,
}

fn expected(case: Case) -> Expected {
	use Boundary::{
		DataFlush, DestinationFlush, PrivateFlush, Publish, Readback, SourceRead, StageCreate,
		StageWrite,
	};
	use CopyPhase::{Conflict, DurabilityConfirmed, IoFailed, RecoveryRequired};
	use Race::{Absent, Incumbent, Rebound};
	use Script::{After, Before, Pass};

	let pass = matches!(case.script, Pass);
	let after = matches!(case.script, After(_));
	match (case.at, case.race) {
		(StageCreate | SourceRead | StageWrite | DataFlush | Readback, _) if !pass => Expected {
			phase: IoFailed,
			live_target: false,
			stable_target: false,
			stable_stage: false,
			intent: false,
		},
		(_, Incumbent) => Expected {
			phase: Conflict,
			live_target: true,
			stable_target: true,
			stable_stage: true,
			intent: true,
		},
		(_, Rebound) => Expected {
			phase: RecoveryRequired,
			live_target: false,
			stable_target: false,
			stable_stage: true,
			intent: true,
		},
		(Publish, Absent) if !pass => Expected {
			phase: RecoveryRequired,
			live_target: after,
			stable_target: false,
			stable_stage: true,
			intent: true,
		},
		(DestinationFlush, Absent) if !pass => Expected {
			phase: RecoveryRequired,
			live_target: true,
			stable_target: after,
			stable_stage: false,
			intent: true,
		},
		(PrivateFlush, Absent) if !pass => Expected {
			phase: RecoveryRequired,
			live_target: true,
			stable_target: true,
			stable_stage: matches!(case.script, Before(_)),
			intent: true,
		},
		(_, Absent) => Expected {
			phase: DurabilityConfirmed,
			live_target: true,
			stable_target: true,
			stable_stage: false,
			intent: true,
		},
	}
}

#[test]
fn observed_outcomes_preserve_user_bytes_across_the_bounded_failure_matrix() {
	for at in [
		Boundary::StageCreate,
		Boundary::SourceRead,
		Boundary::StageWrite,
		Boundary::DataFlush,
		Boundary::Readback,
		Boundary::Publish,
		Boundary::DestinationFlush,
		Boundary::PrivateFlush,
	] {
		for script in [
			Script::Pass,
			Script::Before(Failure::Io),
			Script::After(Failure::Io),
			Script::Before(Failure::NoSpace),
			Script::After(Failure::NoSpace),
		] {
			for race in [Race::Absent, Race::Incumbent, Race::Rebound] {
				let case = Case { at, script, race };
				let mut fixture = Fixture::new();
				fixture.copy(case);
				let oracle = expected(case);
				assert_eq!(fixture.phase(), oracle.phase, "{case:?}");
				assert_eq!(fixture.has_stable_intent(), oracle.intent, "{case:?}");
				let live = fixture.disk.live_snapshot();
				let stable = fixture.disk.stable_snapshot();
				for (snapshot, public_target) in
					[(&live, oracle.live_target), (&stable, oracle.stable_target)]
				{
					assert!(
						fixture.file_in(snapshot, Area::Source, fixture.source_id, CONTENTS),
						"{case:?}"
					);
					let target = snapshot.entry(Area::Destination, &fixture.target);
					assert_eq!(target.is_some(), public_target, "{case:?}");
					if let Some(incumbent) = fixture.incumbent_id {
						assert!(
							fixture.file_in(snapshot, Area::Destination, incumbent, INCUMBENT),
							"{case:?}"
						);
					} else if public_target {
						assert!(fixture.valid_publication(snapshot), "{case:?}");
					}
				}
				if oracle.phase == CopyPhase::IoFailed {
					let private_bytes: Option<&[u8]> = match (case.at, case.script) {
						(Boundary::StageCreate, Script::Before(_)) => None,
						(Boundary::StageCreate | Boundary::SourceRead, _) => Some(b""),
						(Boundary::StageWrite, Script::Before(_)) => Some(&CONTENTS[..1]),
						(Boundary::StageWrite, Script::After(_)) => Some(&CONTENTS[..3]),
						_ => Some(CONTENTS),
					};
					let observed = live.entry(Area::Private, &fixture.stage);
					let observed_bytes = observed.map(|entry| match entry {
						Entry::File(file) => file.bytes,
						Entry::Symlink => {
							panic!("ordinary staging manufactured a symlink: {case:?}")
						}
					});
					assert_eq!(observed_bytes, private_bytes, "{case:?}");
				}
				if oracle.stable_stage {
					assert!(
						fixture.file_in(
							&stable,
							Area::Private,
							fixture.stage_id.unwrap(),
							CONTENTS
						),
						"{case:?}"
					);
				} else {
					assert_eq!(
						stable.entry(Area::Private, &fixture.stage),
						None,
						"{case:?}"
					);
				}
				if let Some(rebound) = fixture.rebound_id {
					assert!(
						fixture.file_in(&live, Area::Private, rebound, REBOUND),
						"{case:?}"
					);
				}
				fixture.disk.process_crash();
				assert_eq!(fixture.disk.live_snapshot(), live, "{case:?}");
				fixture.disk.lose_volatile_state();
				assert_eq!(fixture.disk.live_snapshot(), stable, "{case:?}");
			}
		}
	}
}

#[test]
fn the_namespace_oracle_rejects_an_adapter_call_bypassing_the_model() {
	let mut fixture = Fixture::new();
	let writer = fixture
		.disk
		.create_stage(&fixture.stage, &fixture.target)
		.unwrap();
	fixture.stage_id = Some(writer.identity());
	fixture.disk.write_at(&writer, 0, CONTENTS).unwrap();
	// Negative control: directly call the primitive without read-back or durable intent.
	fixture.disk.publish_no_clobber(writer.quiesce()).unwrap();
	let observed = fixture.disk.live_snapshot();
	assert!(observed.entry(Area::Destination, &fixture.target).is_some());
	assert!(!fixture.valid_publication(&observed));
}

#[test]
fn a_failed_stage_file_barrier_is_never_retried_by_the_attempt() {
	for first in [
		EffectFault::Before(Failure::Io),
		EffectFault::After(Failure::Io),
	] {
		let mut fixture = Fixture::new();
		let incumbent = fixture
			.disk
			.seed_file(Area::Destination, &fixture.target, INCUMBENT)
			.unwrap();
		fixture
			.disk
			.inject_effect(EffectOperation::FlushFile, first)
			.unwrap();
		// Only a later independent barrier should receive the next reply.
		fixture
			.disk
			.inject_effect(
				EffectOperation::FlushFile,
				EffectFault::After(Failure::NoSpace),
			)
			.unwrap();
		fixture.copy(Case {
			at: Boundary::StageCreate,
			script: Script::Pass,
			race: Race::Absent,
		});
		assert_eq!(fixture.phase(), CopyPhase::IoFailed, "{first:?}");
		assert!(!fixture.has_stable_intent(), "{first:?}");
		for snapshot in [fixture.disk.live_snapshot(), fixture.disk.stable_snapshot()] {
			assert!(
				fixture.file_in(&snapshot, Area::Source, fixture.source_id, CONTENTS),
				"{first:?}"
			);
			assert!(
				fixture.file_in(&snapshot, Area::Destination, incumbent, INCUMBENT),
				"{first:?}"
			);
		}
		let name = UnixComponent::new(b"independent").unwrap();
		let witness = fixture.disk.create_stage(&name, &name).unwrap().quiesce();
		assert_eq!(
			fixture.disk.flush_file(&witness),
			Err(EffectError::Unknown(Failure::NoSpace)),
			"{first:?}"
		);
	}
}
