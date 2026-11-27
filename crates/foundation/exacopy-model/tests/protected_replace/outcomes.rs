use exacopy_core::{EntryId, JobId, RunEpoch, StageId};
use exacopy_model::CopyBinding;
use exacopy_model::protected_replace::{
	CaptureOutcome, CaptureRecord, Durable, Entry, EntryKind, FilesystemId, ImageObservation,
	ImagePolicy, ObjectId, Phase, PublicationOutcome, PublishIntent, Refusal, Session,
};

use super::fixture::{
	FOREIGN, Fixture, IMAGE, RESTORED_ORIGINAL, SOURCE, STAGE, VERIFIED, ack, directory, entry,
	grant, head, independent_image, slot, terminal,
};

const UNKNOWN_OBJECT: ObjectId = ObjectId([0; 32]);
const DONOR_CAPTURE_PREDECESSOR: u8 = 11;
const DONOR_CAPTURE_HEAD: u8 = DONOR_CAPTURE_PREDECESSOR + 1;
const DONOR_RECORD_HEAD: u8 = DONOR_CAPTURE_HEAD + 1;

fn disjoint_donor() -> Fixture {
	let mut donor = Fixture::new(ImagePolicy::RetainObject);
	let donor_source = FilesystemId([41; 32]);
	let donor_destination = FilesystemId([42; 32]);
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2]).unwrap();
	let mut context = donor.selection.context;
	context.attempt = CopyBinding::new(
		job,
		EntryId::new(5),
		RunEpoch::new(3),
		StageId::from_bytes([2; 16]),
	);
	context.plan = [43; 32];
	context.lease = [44; 32];
	context.layout = [56; 32];
	context.source_root = directory(45, donor_source);
	context.target.parent = directory(46, donor_destination);
	context.stage.parent = directory(47, donor_destination);
	context.recovery.parent = directory(48, donor_destination);
	donor.selection.context = context;
	donor.selection.source = ObjectId([49; 32]);
	donor.selection.replacement = ObjectId([50; 32]);
	donor.selection.incumbent = ObjectId([51; 32]);
	donor.selection.capture = grant(52);
	donor.selection.publication = grant(53);
	donor.stage.context = context;
	donor.stage.object = donor.selection.replacement;
	donor
}

fn start_donor(donor: &Fixture) -> Session<'static> {
	Session::start(
		donor.selection,
		entry(donor.selection.context.target, donor.selection.incumbent),
		donor.stage,
		donor.history(head(DONOR_CAPTURE_PREDECESSOR)),
	)
	.unwrap()
}

#[test]
fn capture_report_cannot_use_the_permit_for_a_disjoint_attempt() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let donor = disjoint_donor();
	let mut donor_session = start_donor(&donor);
	let donor_intent = donor_session.capture_intent().unwrap();
	let other_permit = donor_session
		.authorize_capture(
			donor.stage,
			donor.current(donor.selection.capture),
			ack(DONOR_CAPTURE_PREDECESSOR, donor_intent),
		)
		.unwrap();

	let mut session = fixture.start();
	let issued = fixture.authorize_capture(&mut session);
	let report = CaptureOutcome::Captured(fixture.actual(RESTORED_ORIGINAL));
	assert_eq!(
		session.observe_capture(other_permit, report),
		Err(Refusal::Evidence)
	);
	assert_eq!(session.last_captured(), None);
	assert_eq!(session.observe_capture(issued, report), Err(Refusal::Order));
	terminal(&mut session, Phase::ReconciliationRequired);
}

#[test]
fn capture_requires_a_known_identity_in_the_held_recovery_directory() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let mut session = fixture.start();
	let permit = fixture.authorize_capture(&mut session);
	let report = CaptureOutcome::Captured(fixture.actual(UNKNOWN_OBJECT));
	assert_eq!(
		session.observe_capture(permit, report),
		Err(Refusal::Evidence)
	);
	assert_eq!(session.last_captured(), None);
	terminal(&mut session, Phase::ReconciliationRequired);
}

#[test]
fn postbarrier_record_must_extend_the_exact_capture_head() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let actual = fixture.actual(RESTORED_ORIGINAL);
	let valid = ack(2, fixture.capture_record(actual));
	let defects: [(&str, fn(&mut Durable<CaptureRecord<'static>>)); 3] = [
		("stale embedded capture head", |durable| {
			durable.record.capture_head = head(1);
		}),
		("skipped journal successor", |durable| {
			durable.current = head(4);
		}),
		("unknown successor digest", |durable| {
			durable.current.digest = [0; 32];
		}),
	];
	for (case, alter) in defects {
		let mut session = fixture.start();
		fixture.capture(&mut session, actual);
		let mut wrong = valid;
		alter(&mut wrong);
		assert_eq!(
			session.acknowledge_capture(wrong),
			Err(Refusal::Evidence),
			"{case}"
		);
		assert_eq!(
			session.acknowledge_capture(valid),
			Err(Refusal::Order),
			"{case}"
		);
		assert_eq!(session.last_captured(), Some(actual), "{case}");
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn image_identity_cannot_alias_a_protected_file_or_held_root() {
	let fixture = Fixture::new(independent_image());
	let context = fixture.selection.context;
	for (case, id) in [
		("unknown", UNKNOWN_OBJECT),
		("held source directory", context.source_root.id),
		("held public directory", context.target.parent.id),
		("held stage directory", context.stage.parent.id),
		("held recovery directory", context.recovery.parent.id),
		("source file", SOURCE),
		("replacement file", STAGE),
	] {
		let mut session = fixture.verified_capture();
		let image = ImageObservation {
			image: id,
			..fixture.image()
		};
		assert_eq!(
			session.acknowledge_image(image),
			Err(Refusal::Image),
			"{case}"
		);
		assert_eq!(session.last_captured(), Some(image.captured), "{case}");
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn image_cannot_use_a_stale_capture_or_expired_object_authority() {
	let fixture = Fixture::new(independent_image());
	let actual = fixture.actual(RESTORED_ORIGINAL);
	let defects: [(&str, fn(&mut ImageObservation<'static>)); 3] = [
		("approved inode reported at a different slot", |image| {
			image.captured.slot = image.read.context.target;
		}),
		("read grant expires at its exclusive deadline", |image| {
			image.read.now = image.read.grant.expires_before.get();
		}),
		(
			"creation grant expires at its exclusive deadline",
			|image| {
				image.create.now = image.create.grant.expires_before.get();
			},
		),
	];
	for (case, alter) in defects {
		let mut session = fixture.verified_capture();
		let mut image = fixture.image();
		alter(&mut image);
		assert_eq!(
			session.acknowledge_image(image),
			Err(Refusal::Image),
			"{case}"
		);
		assert_eq!(
			session.acknowledge_image(fixture.image()),
			Err(Refusal::Order),
			"{case}"
		);
		assert_eq!(session.last_captured(), Some(actual), "{case}");
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn image_policy_and_independently_retained_image_bind_the_publication_permit() {
	let retain_only = Fixture::new(ImagePolicy::RetainObject);
	let mut session = retain_only.verified_capture();
	assert_eq!(
		session.acknowledge_image(retain_only.image()),
		Err(Refusal::Order)
	);
	assert_eq!(session.publish_intent().unwrap().image, None);

	let fixture = Fixture::new(independent_image());
	let mut image = fixture.image();
	image.original.byte_len = VERIFIED.byte_len - 1;
	image.measured = image.original;
	let anticipated = PublishIntent {
		selection: fixture.selection,
		captured: image.captured,
		image: Some(IMAGE),
	};
	let authority = fixture.current(fixture.selection.publication);
	let ready = fixture.publication_ready(anticipated);
	let mut session = fixture.verified_capture();
	assert_eq!(
		session.authorize_publication(ready, authority, ack(3, anticipated)),
		Err(Refusal::Order)
	);
	assert_eq!(session.phase(), Phase::CaptureRecorded);
	session.acknowledge_image(image).unwrap();
	assert_eq!(session.phase(), Phase::ImageReady);
	assert_eq!(session.publish_intent(), Some(anticipated));
	let publication = fixture.authorize_publication(&mut session);
	assert_eq!(publication.intent(), anticipated);
	session
		.observe_publication(
			publication,
			PublicationOutcome::Placed {
				target: entry(fixture.selection.context.target, STAGE),
				stage_absent: true,
				retained: anticipated.captured,
			},
		)
		.unwrap();
	assert_eq!(session.last_captured(), Some(anticipated.captured));
	terminal(&mut session, Phase::PlacedUnconfirmed);

	for (case, retained_image, recorded_image) in [
		("image no longer observed", None, Some(IMAGE)),
		(
			"image rebound before publication",
			Some(FOREIGN),
			Some(IMAGE),
		),
		(
			"journal describes a different image",
			Some(IMAGE),
			Some(FOREIGN),
		),
	] {
		let mut session = fixture.verified_capture();
		session.acknowledge_image(image).unwrap();
		let mut ready = ready;
		ready.retained_image = retained_image;
		let recorded = PublishIntent {
			image: recorded_image,
			..anticipated
		};
		assert_eq!(
			session.authorize_publication(ready, authority, ack(3, recorded)),
			Err(Refusal::Evidence),
			"{case}"
		);
		assert_eq!(
			session.last_captured(),
			Some(anticipated.captured),
			"{case}"
		);
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn publication_report_cannot_use_the_permit_for_a_disjoint_attempt() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let donor = disjoint_donor();
	let mut donor_session = start_donor(&donor);
	let donor_capture = donor_session.capture_intent().unwrap();
	let donor_permit = donor_session
		.authorize_capture(
			donor.stage,
			donor.current(donor.selection.capture),
			ack(DONOR_CAPTURE_PREDECESSOR, donor_capture),
		)
		.unwrap();
	let donor_retained = donor.actual(donor.selection.incumbent);
	donor_session
		.observe_capture(donor_permit, CaptureOutcome::Captured(donor_retained))
		.unwrap();
	let mut donor_record = donor.capture_record(donor_retained);
	donor_record.capture_head = head(DONOR_CAPTURE_HEAD);
	donor_session
		.acknowledge_capture(ack(DONOR_CAPTURE_HEAD, donor_record))
		.unwrap();
	let donor_intent = donor_session.publish_intent().unwrap();
	let other_permit = donor_session
		.authorize_publication(
			donor.publication_ready(donor_intent),
			donor.current(donor.selection.publication),
			ack(DONOR_RECORD_HEAD, donor_intent),
		)
		.unwrap();

	let mut session = fixture.verified_capture();
	let issued = fixture.authorize_publication(&mut session);
	let retained = fixture.actual(RESTORED_ORIGINAL);
	let report = PublicationOutcome::Placed {
		target: entry(fixture.selection.context.target, STAGE),
		stage_absent: true,
		retained,
	};
	assert_eq!(
		session.observe_publication(other_permit, report),
		Err(Refusal::Evidence)
	);
	assert_eq!(
		session.observe_publication(issued, report),
		Err(Refusal::Order)
	);
	assert_eq!(session.last_captured(), Some(retained));
	terminal(&mut session, Phase::ReconciliationRequired);
}

#[test]
fn a_publication_conflict_requires_the_arrival_and_both_preserved_objects() {
	let fixture = Fixture::new(ImagePolicy::RetainObject);
	let context = fixture.selection.context;
	let arrival = Entry {
		kind: EntryKind::Opaque,
		..entry(context.target, FOREIGN)
	};
	let stage = entry(context.stage, STAGE);
	let retained = fixture.actual(RESTORED_ORIGINAL);
	let mut session = fixture.verified_capture();
	let permit = fixture.authorize_publication(&mut session);
	session
		.observe_publication(
			permit,
			PublicationOutcome::Conflict {
				target: arrival,
				stage,
				retained,
			},
		)
		.unwrap();
	assert_eq!(session.last_captured(), Some(retained));
	terminal(&mut session, Phase::Conflict);

	let unselected = slot(54, b"unselected");
	let other_object = ObjectId([55; 32]);
	for (case, target, stage, retained_report) in [
		(
			"arrival at wrong slot",
			entry(unselected, FOREIGN),
			stage,
			retained,
		),
		(
			"unknown arrival",
			entry(context.target, UNKNOWN_OBJECT),
			stage,
			retained,
		),
		(
			"stage at wrong slot",
			arrival,
			entry(unselected, STAGE),
			retained,
		),
		(
			"wrong private stage",
			arrival,
			entry(context.stage, other_object),
			retained,
		),
		(
			"original replaced in the recovery slot",
			arrival,
			stage,
			fixture.actual(other_object),
		),
	] {
		let mut session = fixture.verified_capture();
		let permit = fixture.authorize_publication(&mut session);
		let report = PublicationOutcome::Conflict {
			target,
			stage,
			retained: retained_report,
		};
		assert_eq!(
			session.observe_publication(permit, report),
			Err(Refusal::Evidence),
			"{case}"
		);
		assert_eq!(session.last_captured(), Some(retained), "{case}");
		terminal(&mut session, Phase::ReconciliationRequired);
	}
}

#[test]
fn interrupting_after_capture_keeps_the_observation_and_refuses_late_evidence() {
	let fixture = Fixture::new(independent_image());
	let retained = fixture.actual(RESTORED_ORIGINAL);

	let mut session = fixture.start();
	fixture.capture(&mut session, retained);
	session.interrupt();
	assert_eq!(
		session.acknowledge_capture(ack(2, fixture.capture_record(retained))),
		Err(Refusal::Order)
	);
	assert_eq!(session.last_captured(), Some(retained));
	terminal(&mut session, Phase::ReconciliationRequired);

	let mut session = fixture.verified_capture();
	session.interrupt();
	assert_eq!(
		session.acknowledge_image(fixture.image()),
		Err(Refusal::Order)
	);
	assert_eq!(session.last_captured(), Some(retained));
	terminal(&mut session, Phase::ReconciliationRequired);

	let mut session = fixture.verified_capture();
	session.acknowledge_image(fixture.image()).unwrap();
	let intent = session.publish_intent().unwrap();
	session.interrupt();
	assert_eq!(
		session.authorize_publication(
			fixture.publication_ready(intent),
			fixture.current(fixture.selection.publication),
			ack(3, intent),
		),
		Err(Refusal::Order)
	);
	assert_eq!(session.last_captured(), Some(retained));
	terminal(&mut session, Phase::ReconciliationRequired);
}
