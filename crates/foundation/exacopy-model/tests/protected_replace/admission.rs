//! Admission and durable capture-intent regressions for the protected-slot profile.

use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use exacopy_model::protected_replace::{
	CaptureIntent, CurrentGrant, Durable, Entry, EntryKind, FilesystemId, Grant, ImagePolicy,
	JournalHead, ObjectId, Phase, Refusal, Selection, Session, Slot, StageReady,
};
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};

use super::fixture::{FOREIGN, Fixture, ack, head, independent_image, terminal};

// The protected profile admits extents representable as signed file offsets.
const SIGNED_FILE_LIMIT: u64 = i64::MAX as u64;

#[test]
fn admission_refuses_unidentified_scope_and_aliased_roles() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	type ChangeSelection = fn(&mut Selection<'static>);
	let invalid_scopes: [(&str, ChangeSelection); 11] = [
		("unidentified public filesystem", |selected| {
			selected.context.target.parent.filesystem = FilesystemId([0; 32]);
			selected.context.stage.parent.filesystem = FilesystemId([0; 32]);
			selected.context.recovery.parent.filesystem = FilesystemId([0; 32]);
		}),
		("unidentified source filesystem", |selected| {
			selected.context.source_root.filesystem = FilesystemId([0; 32]);
		}),
		("staging parent on the source filesystem", |selected| {
			selected.context.stage.parent.filesystem = selected.context.source_root.filesystem;
		}),
		("unidentified qualification", |selected| {
			selected.context.qualification = [0; 32];
		}),
		("unidentified plan", |selected| {
			selected.context.plan = [0; 32]
		}),
		("unidentified lease", |selected| {
			selected.context.lease = [0; 32]
		}),
		("unidentified recovery parent", |selected| {
			selected.context.recovery.parent.id = ObjectId([0; 32]);
		}),
		("incumbent is the stage", |selected| {
			selected.incumbent = selected.replacement;
		}),
		("incumbent is the recovery parent", |selected| {
			selected.incumbent = selected.context.recovery.parent.id;
		}),
		("unidentified source file", |selected| {
			selected.source = ObjectId([0; 32])
		}),
		("unidentified capture grant", |selected| {
			selected.capture.id = [0; 32]
		}),
	];
	for (case, invalidate) in invalid_scopes {
		let mut selected = fixture.selection;
		invalidate(&mut selected);
		let observed = Entry {
			slot: selected.context.target,
			object: selected.incumbent,
			..fixture.incumbent()
		};
		let stage = StageReady {
			context: selected.context,
			..fixture.stage
		};
		let mut history = fixture.history(head(1));
		history.context = selected.context;
		assert_eq!(
			Session::start(selected, observed, stage, history).expect_err(case),
			Refusal::Selection,
			"{case}"
		);
	}
}

#[test]
fn admission_enforces_each_signed_extent_ceiling_and_separate_image_grant_ids() {
	let base = Fixture::new(independent_image());
	let ImagePolicy::IndependentImage { read, create, .. } = base.selection.image else {
		panic!("fixture must require an independent image");
	};
	let fixture = Fixture {
		selection: Selection {
			max_replacement_bytes: SIGNED_FILE_LIMIT,
			image: ImagePolicy::IndependentImage {
				read,
				create,
				max_bytes: SIGNED_FILE_LIMIT,
			},
			..base.selection
		},
		..base
	};
	assert_eq!(fixture.start().phase(), Phase::Prepared);

	for (case, selected) in [
		(
			"replacement budget outside the signed extent",
			Selection {
				max_replacement_bytes: SIGNED_FILE_LIMIT + 1,
				..fixture.selection
			},
		),
		(
			"image budget outside the signed extent",
			Selection {
				image: ImagePolicy::IndependentImage {
					read,
					create,
					max_bytes: SIGNED_FILE_LIMIT + 1,
				},
				..fixture.selection
			},
		),
		(
			"image grants share an ID across revisions",
			Selection {
				image: ImagePolicy::IndependentImage {
					read,
					create: Grant {
						id: read.id,
						revision: NonZeroU64::new(2).expect("nonzero revised grant"),
						..create
					},
					max_bytes: SIGNED_FILE_LIMIT,
				},
				..fixture.selection
			},
		),
	] {
		assert_eq!(
			Session::start(
				selected,
				fixture.incumbent(),
				fixture.stage,
				fixture.history(head(1)),
			)
			.expect_err(case),
			Refusal::Selection,
			"{case}"
		);
	}
}

#[test]
fn prelookup_requires_the_regular_entry_at_the_literal_public_slot() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let public = fixture.incumbent();
	for (case, observed) in [
		(
			"matching identity at a different raw name",
			Entry {
				slot: Slot {
					name: UnixComponent::new(b"Public-exact").expect("valid literal name"),
					..public.slot
				},
				..public
			},
		),
		(
			"matching identity at a different held parent",
			Entry {
				slot: Slot {
					parent: fixture.selection.context.recovery.parent,
					..public.slot
				},
				..public
			},
		),
		(
			"incumbent reported outside the ordinary-file profile",
			Entry {
				kind: EntryKind::Opaque,
				..public
			},
		),
	] {
		assert_eq!(
			Session::start(
				fixture.selection,
				observed,
				fixture.stage,
				fixture.history(head(1)),
			)
			.expect_err(case),
			Refusal::Incumbent,
			"{case}"
		);
	}
}

#[test]
fn a_new_run_epoch_cannot_reuse_old_history_stage_or_live_capture_authority() {
	let job = JobId::try_from_bytes([1, 2, 3, 4, 5, 6, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 9])
		.expect("synthetic job is a valid UUIDv7");
	let entry = EntryId::new(7);
	let stage = StageId::from_bytes([9; 16]);
	let [previous, next] = [RunEpoch::new(2), RunEpoch::new(3)].map(|epoch| {
		let mut fixture = Fixture::new(ImagePolicy::RetainObject);
		fixture.selection.context.attempt = CopyBinding::new(job, entry, epoch, stage);
		fixture.stage.context = fixture.selection.context;
		fixture
	});

	assert_eq!(
		Session::start(
			next.selection,
			next.incumbent(),
			next.stage,
			previous.history(head(1)),
		)
		.expect_err("previous epoch's replay"),
		Refusal::History
	);
	assert_eq!(
		Session::start(
			next.selection,
			next.incumbent(),
			previous.stage,
			next.history(head(1)),
		)
		.expect_err("previous epoch's seal"),
		Refusal::Stage
	);

	let mut session = next.start();
	let intent = session.capture_intent().expect("newly prepared intent");
	assert_eq!(
		session.authorize_capture(
			next.stage,
			previous.current(previous.selection.capture),
			ack(1, intent),
		),
		Err(Refusal::Authority)
	);
	terminal(&mut session, Phase::ReconciliationRequired);
}

#[test]
fn capture_rechecks_exact_readback_and_the_approved_deadline() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let mut stage = fixture.stage;
	stage.measured.content_digest = FOREIGN.0;
	let mut session = fixture.start();
	let intent = session.capture_intent().expect("prepared capture intent");
	assert_eq!(
		session.authorize_capture(
			stage,
			fixture.current(fixture.selection.capture),
			ack(1, intent),
		),
		Err(Refusal::Stage)
	);
	terminal(&mut session, Phase::ReconciliationRequired);

	let mut session = fixture.start();
	let live = fixture.current(fixture.selection.capture);
	let changed_deadline = CurrentGrant {
		grant: Grant {
			expires_before: live.grant.expires_before.saturating_add(1),
			..live.grant
		},
		..live
	};
	assert_eq!(
		session.authorize_capture(fixture.stage, changed_deadline, ack(1, intent)),
		Err(Refusal::Authority)
	);
	terminal(&mut session, Phase::ReconciliationRequired);

	let mut session = fixture.start();
	let last_valid_instant = CurrentGrant {
		now: live.grant.expires_before.get() - 1,
		..live
	};
	let permit = session
		.authorize_capture(fixture.stage, last_valid_instant, ack(1, intent))
		.expect("capture grant is live just before its deadline");
	assert_eq!(permit.intent(), intent);
	assert_eq!(session.phase(), Phase::CaptureIssued);
	assert!(session.publish_intent().is_none());
}

#[test]
fn journal_admission_requires_an_anchored_head_with_room_for_three_successors() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	for (case, unanchored) in [
		(
			"zero sequence",
			JournalHead {
				sequence: 0,
				..head(1)
			},
		),
		(
			"zero digest",
			JournalHead {
				digest: [0; 32],
				..head(1)
			},
		),
	] {
		assert_eq!(
			Session::start(
				fixture.selection,
				fixture.incumbent(),
				fixture.stage,
				fixture.history(unanchored),
			)
			.expect_err(case),
			Refusal::Evidence,
			"{case}"
		);
	}

	let latest_start = JournalHead {
		sequence: u64::MAX - 3,
		..head(1)
	};
	let mut session = Session::start(
		fixture.selection,
		fixture.incumbent(),
		fixture.stage,
		fixture.history(latest_start),
	)
	.expect("the journal has exactly three successor positions");
	let approved = CaptureIntent {
		selection: fixture.selection,
	};
	assert_eq!(session.capture_intent(), Some(approved));
	let successor = JournalHead {
		sequence: u64::MAX - 2,
		..head(2)
	};
	let permit = session
		.authorize_capture(
			fixture.stage,
			fixture.current(fixture.selection.capture),
			Durable {
				previous: latest_start,
				current: successor,
				record: approved,
			},
		)
		.expect("the first successor is the durable capture intent");
	assert_eq!(permit.head(), successor);
	assert_eq!(permit.intent(), approved);
	assert_eq!(session.phase(), Phase::CaptureIssued);
}

#[test]
fn malformed_capture_intent_chain_or_contents_require_reconciliation() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	type ChangeRecord = fn(&mut Durable<CaptureIntent<'static>>);
	let invalid_records: [(&str, ChangeRecord); 5] = [
		("different predecessor digest at the same sequence", |ack| {
			ack.previous.digest = FOREIGN.0;
		}),
		("skipped sequence after the exact predecessor", |ack| {
			ack.current.sequence += 1;
		}),
		("unidentified successor digest", |ack| {
			ack.current.digest = [0; 32]
		}),
		("record authorizes another source", |ack| {
			ack.record.selection.source = FOREIGN;
		}),
		("record carries another replacement budget", |ack| {
			ack.record.selection.max_replacement_bytes += 1;
		}),
	];
	for (case, invalidate) in invalid_records {
		let mut session = fixture.start();
		let intent = session.capture_intent().expect("prepared capture intent");
		let proof = ack(1, intent);
		let mut malformed = proof;
		invalidate(&mut malformed);
		let live = fixture.current(fixture.selection.capture);
		assert_eq!(
			session.authorize_capture(fixture.stage, live, malformed),
			Err(Refusal::Evidence),
			"{case}"
		);
		terminal(&mut session, Phase::ReconciliationRequired);
		assert_eq!(
			session.authorize_capture(fixture.stage, live, proof),
			Err(Refusal::Order),
			"{case}: corrected evidence cannot revive this attempt"
		);
	}
}
