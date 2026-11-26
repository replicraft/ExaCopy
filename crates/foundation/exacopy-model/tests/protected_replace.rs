//! Model transition tests for one bounded protected-slot relocation.

use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use exacopy_model::protected_replace::{
	AdmissionHistory, CaptureIntent, CaptureOutcome, CaptureRecord, CurrentGrant, Durable, Entry,
	EntryKind, HistoryDisposition, ImageObservation, ImagePolicy, JournalHead, Phase,
	PublicationOutcome, ReadyForPublication, Refusal, Selection, Session, StageReady,
};

#[path = "protected_replace/fixture.rs"]
mod fixture;

use fixture::{
	CAPTURE_GRANT, DEST_FS, FOREIGN, Fixture, IMAGE, IMAGE_READ_GRANT, PUBLICATION_GRANT,
	RESTORED_ORIGINAL, SOURCE, SOURCE_FS, STAGE, VERIFIED, ack, directory, entry, grant, head,
	independent_image, terminal,
};

#[test]
fn protected_slot_needs_every_stage_and_authorization_prerequisite() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let invalid_stages: [fn(&mut StageReady<'static>); 7] = [
		|stage| stage.quiesced = false,
		|stage| stage.data_flushed = false,
		|stage| stage.independently_verified = false,
		|stage| stage.metadata_ready = false,
		|stage| stage.sealed = false,
		|stage| stage.measured.required_metadata_digest = [0; 32],
		|stage| stage.object = SOURCE,
	];
	for invalidate in invalid_stages {
		let mut stage = fixture.stage;
		invalidate(&mut stage);
		assert!(matches!(
			Session::start(
				fixture.selection,
				fixture.incumbent(),
				stage,
				fixture.history(head(1))
			),
			Err(Refusal::Stage)
		));
		let mut session = fixture.start();
		let intent = session.capture_intent().unwrap();
		assert_eq!(
			session.authorize_capture(
				stage,
				fixture.current(fixture.selection.capture),
				ack(1, intent)
			),
			Err(Refusal::Stage)
		);
		terminal(&mut session, Phase::ReconciliationRequired);
	}
	let mut stage = fixture.stage;
	stage.context.lease = [92; 32];
	assert!(matches!(
		Session::start(
			fixture.selection,
			fixture.incumbent(),
			stage,
			fixture.history(head(1))
		),
		Err(Refusal::Stage)
	));

	let invalid_grants: [fn(&mut CurrentGrant<'static>); 5] = [
		|live| live.now = live.grant.expires_before.get(),
		|live| live.grant = grant(PUBLICATION_GRANT),
		|live| live.grant.revision = NonZeroU64::new(2).unwrap(),
		|live| live.context.layout = [99; 32],
		|live| live.context.qualification = [99; 32],
	];
	for invalidate in invalid_grants {
		let mut live = fixture.current(fixture.selection.capture);
		invalidate(&mut live);
		let mut session = fixture.start();
		let intent = session.capture_intent().unwrap();
		assert_eq!(
			session.authorize_capture(fixture.stage, live, ack(1, intent)),
			Err(Refusal::Authority)
		);
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn isolated_source_and_exact_scope_are_required() {
	let fixture = Fixture::new(independent_image());
	let invalid_selections: [fn(&mut Selection<'static>); 9] = [
		|selection| selection.source = selection.incumbent,
		|selection| selection.replacement = selection.context.target.parent.id,
		|selection| selection.context.source_root.filesystem = DEST_FS,
		|selection| selection.context.stage.parent = selection.context.target.parent,
		|selection| selection.context.recovery.parent.filesystem = SOURCE_FS,
		|selection| selection.context.layout = [0; 32],
		|selection| selection.capture = selection.publication,
		|selection| selection.capture = grant(IMAGE_READ_GRANT),
		|selection| selection.max_replacement_bytes = VERIFIED.byte_len - 1,
	];
	for invalidate in invalid_selections {
		let mut selection = fixture.selection;
		invalidate(&mut selection);
		assert!(matches!(
			Session::start(
				selection,
				fixture.incumbent(),
				fixture.stage,
				fixture.history(head(1))
			),
			Err(Refusal::Selection)
		));
	}
	let initial_foreign = entry(fixture.selection.context.target, FOREIGN);
	assert!(matches!(
		Session::start(
			fixture.selection,
			initial_foreign,
			fixture.stage,
			fixture.history(head(1))
		),
		Err(Refusal::Incumbent)
	));
	let exhausted = JournalHead {
		sequence: u64::MAX - 2,
		..head(1)
	};
	assert!(matches!(
		Session::start(
			fixture.selection,
			fixture.incumbent(),
			fixture.stage,
			fixture.history(exhausted)
		),
		Err(Refusal::Evidence)
	));
}

#[test]
fn capture_intent_binds_exact_head_and_reserved_raw_name_and_is_one_shot() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let mut session = fixture.start();
	let mut altered = session.capture_intent().unwrap();
	altered.selection.context.recovery.name = UnixComponent::new(b"Version-exact").unwrap();
	assert_eq!(
		session.authorize_capture(
			fixture.stage,
			fixture.current(fixture.selection.capture),
			ack(1, altered)
		),
		Err(Refusal::Evidence)
	);
	terminal(&mut session, Phase::ReconciliationRequired);

	let mut session = fixture.start();
	let intent: CaptureIntent<'static> = session.capture_intent().unwrap();
	let permit = fixture.authorize_capture(&mut session);
	assert_eq!(
		session.authorize_capture(
			fixture.stage,
			fixture.current(fixture.selection.capture),
			ack(1, intent)
		),
		Err(Refusal::Order)
	);
	session
		.observe_capture(permit, CaptureOutcome::NoEffect)
		.unwrap();
	terminal(&mut session, Phase::Conflict);
}

#[test]
fn actual_foreign_and_unsupported_captures_are_preserved_without_publication() {
	let fixture = Fixture::new(independent_image());
	for actual in [
		fixture.actual(FOREIGN),
		fixture.actual(SOURCE),
		fixture.actual(STAGE),
		Entry {
			kind: EntryKind::Opaque,
			..fixture.actual(RESTORED_ORIGINAL)
		},
	] {
		let mut session = fixture.start();
		fixture.capture(&mut session, actual);
		let record = fixture.capture_record(actual);
		session.acknowledge_capture(ack(2, record)).unwrap();
		assert_eq!(session.last_captured(), Some(actual));
		assert_eq!(
			session.acknowledge_image(fixture.image()),
			Err(Refusal::Order)
		);
		terminal(&mut session, Phase::StalePlan);
	}
}

#[test]
fn both_capture_barriers_and_the_exact_postbarrier_actual_are_required() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let failures: [fn(&mut Durable<CaptureRecord<'static>>); 6] = [
		|durable| durable.record.observed.barriers.public = directory(99, DEST_FS),
		|durable| durable.record.observed.barriers.recovery = directory(99, DEST_FS),
		|durable| durable.record.observed.retained.object = FOREIGN,
		|durable| durable.record.observed.context.lease = [88; 32],
		|durable| durable.previous = head(1),
		|durable| durable.current.digest = durable.previous.digest,
	];
	for invalidate in failures {
		let actual = fixture.actual(RESTORED_ORIGINAL);
		let mut session = fixture.start();
		fixture.capture(&mut session, actual);
		let mut proof = ack(2, fixture.capture_record(actual));
		invalidate(&mut proof);
		assert_eq!(session.acknowledge_capture(proof), Err(Refusal::Evidence));
		assert_eq!(session.last_captured(), Some(actual));
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn independent_image_requires_special_authority_stable_view_and_distinct_durable_bytes() {
	let fixture = Fixture::new(independent_image());
	let failures: [fn(&mut ImageObservation<'static>); 8] = [
		|image| image.read.grant = image.create.grant,
		|image| image.create.grant = grant(CAPTURE_GRANT),
		|image| image.image = image.captured.object,
		|image| image.stable_view = false,
		|image| image.durably_retained = false,
		|image| image.measured.content_digest = [80; 32],
		|image| image.measured.required_metadata_digest = [80; 32],
		|image| {
			image.measured.byte_len += 1;
			image.original = image.measured;
		},
	];
	for invalidate in failures {
		let mut session = fixture.verified_capture();
		assert!(session.publish_intent().is_none());
		let mut image = fixture.image();
		invalidate(&mut image);
		assert_eq!(session.acknowledge_image(image), Err(Refusal::Image));
		terminal(&mut session, Phase::ReconciliationRequired);
	}

	let mut session = fixture.verified_capture();
	session.acknowledge_image(fixture.image()).unwrap();
	assert_eq!(session.publish_intent().unwrap().image, Some(IMAGE));
	assert_eq!(
		session.acknowledge_image(fixture.image()),
		Err(Refusal::Order)
	);
}

#[test]
fn publication_rechecks_verified_stage_and_retention_under_distinct_live_grant() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let mut session = fixture.verified_capture();
	let intent = session.publish_intent().unwrap();
	assert_eq!(
		session.authorize_publication(
			fixture.publication_ready(intent),
			fixture.current(fixture.selection.capture),
			ack(3, intent),
		),
		Err(Refusal::Authority)
	);
	terminal(&mut session, Phase::ReconciliationRequired);

	for invalidate in [
		(|ready: &mut ReadyForPublication<'static>| ready.retained.object = FOREIGN)
			as fn(&mut ReadyForPublication<'static>),
		|ready| ready.stage.sealed = false,
	] {
		let mut session = fixture.verified_capture();
		let intent = session.publish_intent().unwrap();
		let mut ready = fixture.publication_ready(intent);
		invalidate(&mut ready);
		assert!(
			session
				.authorize_publication(
					ready,
					fixture.current(fixture.selection.publication),
					ack(3, intent),
				)
				.is_err()
		);
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn all_effect_outcomes_are_terminal_and_only_no_clobber_can_place() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let retained = fixture.actual(RESTORED_ORIGINAL);
	let stage = entry(fixture.selection.context.stage, STAGE);
	let target = entry(fixture.selection.context.target, STAGE);
	for (outcome, expected) in [
		(
			PublicationOutcome::Placed {
				target,
				stage_absent: true,
				retained,
			},
			Phase::PlacedUnconfirmed,
		),
		(
			PublicationOutcome::Conflict {
				target: entry(target.slot, FOREIGN),
				stage,
				retained,
			},
			Phase::Conflict,
		),
		(PublicationOutcome::Uncertain, Phase::ReconciliationRequired),
	] {
		let mut session = fixture.verified_capture();
		let intent = session.publish_intent().unwrap();
		let permit = fixture.authorize_publication(&mut session);
		assert_eq!(
			session.authorize_publication(
				fixture.publication_ready(intent),
				fixture.current(fixture.selection.publication),
				ack(3, intent)
			),
			Err(Refusal::Order)
		);
		session.observe_publication(permit, outcome).unwrap();
		terminal(&mut session, expected);
	}

	let mut session = fixture.start();
	let permit = fixture.authorize_capture(&mut session);
	session
		.observe_capture(permit, CaptureOutcome::Uncertain)
		.unwrap();
	terminal(&mut session, Phase::ReconciliationRequired);
}

#[test]
fn interruption_after_a_permit_cannot_accept_late_completion() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let mut session = fixture.start();
	session.interrupt();
	terminal(&mut session, Phase::Cancelled);

	let mut session = fixture.start();
	let permit = fixture.authorize_capture(&mut session);
	session.interrupt();
	assert_eq!(
		session.observe_capture(
			permit,
			CaptureOutcome::Captured(fixture.actual(RESTORED_ORIGINAL))
		),
		Err(Refusal::Order)
	);
	terminal(&mut session, Phase::ReconciliationRequired);

	let mut session = fixture.verified_capture();
	let permit = fixture.authorize_publication(&mut session);
	session.interrupt();
	assert_eq!(
		session.observe_publication(permit, PublicationOutcome::Uncertain),
		Err(Refusal::Order)
	);
	terminal(&mut session, Phase::ReconciliationRequired);
}

#[test]
fn late_wrong_name_or_identity_cannot_become_a_placement() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let context = fixture.selection.context;
	let target = entry(context.target, STAGE);
	let retained = fixture.actual(RESTORED_ORIGINAL);
	for (target, stage_absent, retained) in [
		(entry(context.target, FOREIGN), true, retained),
		(entry(context.stage, STAGE), true, retained),
		(target, false, retained),
		(target, true, fixture.actual(FOREIGN)),
	] {
		let mut session = fixture.verified_capture();
		let permit = fixture.authorize_publication(&mut session);
		let outcome = PublicationOutcome::Placed {
			target,
			stage_absent,
			retained,
		};
		assert_eq!(
			session.observe_publication(permit, outcome),
			Err(Refusal::Evidence)
		);
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn capture_completion_cannot_report_a_different_private_slot() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let mut session = fixture.start();
	let permit = fixture.authorize_capture(&mut session);
	let mut reported = fixture.actual(RESTORED_ORIGINAL);
	reported.slot.name = UnixComponent::new(b"Version-exact").unwrap();
	assert_eq!(
		session.observe_capture(permit, CaptureOutcome::Captured(reported)),
		Err(Refusal::Evidence)
	);
	assert!(session.last_captured().is_none());
	terminal(&mut session, Phase::ReconciliationRequired);
}

#[test]
fn rejects_previously_issued_or_uncertain_history_at_fresh_admission() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);

	let mut prior_session = fixture.start();
	let permit = fixture.authorize_capture(&mut prior_session);
	let issued = permit.head();
	prior_session
		.observe_capture(permit, CaptureOutcome::Uncertain)
		.unwrap();
	terminal(&mut prior_session, Phase::ReconciliationRequired);

	let invalid: [fn(&mut AdmissionHistory<'static>); 7] = [
		|history| history.disposition = HistoryDisposition::PriorIntent,
		|history| history.disposition = HistoryDisposition::Indeterminate,
		|history| history.context.lease = [99; 32],
		|history| history.context.target.name = UnixComponent::new(b"public-other").unwrap(),
		|history| history.replayed.sequence -= 1,
		|history| history.current.digest = [99; 32],
		|history| history.current.sequence += 1,
	];
	for invalidate in invalid {
		let mut history = fixture.history(issued);
		invalidate(&mut history);
		assert!(matches!(
			Session::start(
				fixture.selection,
				fixture.incumbent(),
				fixture.stage,
				history
			),
			Err(Refusal::History)
		));
	}

	let history = fixture.history(head(1));
	let mut session = Session::start(
		fixture.selection,
		fixture.incumbent(),
		fixture.stage,
		history,
	)
	.expect("complete pre-intent replay at the exact live head");
	let intent = session.capture_intent().unwrap();
	assert_eq!(
		session.authorize_capture(
			fixture.stage,
			fixture.current(fixture.selection.capture),
			ack(2, intent),
		),
		Err(Refusal::Evidence)
	);
	terminal(&mut session, Phase::ReconciliationRequired);
}
