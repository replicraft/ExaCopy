use core::num::NonZeroU64;

use exacopy_core::UnixComponent;
use exacopy_model::protected_replace::{
	AdmissionHistory, CaptureBarriers, CaptureObservation, CaptureOutcome, CaptureRecord,
	CaptureSlot, Context, CurrentGrant, Directory, Durable, Entry, EntryKind, FilesystemId, Grant,
	HistoryDisposition, ImageObservation, ImagePolicy, JournalHead, ObjectId, Phase, PublishIntent,
	PublishStage, ReadyForPublication, Selection, Session, Slot, StageReady,
};
use exacopy_model::{CopyBinding, EntryId, JobId, RegularFileEvidence, RunEpoch, StageId};

pub(super) const SOURCE: ObjectId = ObjectId([11; 32]);
pub(super) const RESTORED_ORIGINAL: ObjectId = ObjectId([12; 32]);
pub(super) const STAGE: ObjectId = ObjectId([13; 32]);
pub(super) const FOREIGN: ObjectId = ObjectId([14; 32]);
pub(super) const IMAGE: ObjectId = ObjectId([15; 32]);
pub(super) const CAPTURE_GRANT: u8 = 17;
pub(super) const PUBLICATION_GRANT: u8 = 18;
pub(super) const IMAGE_READ_GRANT: u8 = 19;
pub(super) const IMAGE_CREATE_GRANT: u8 = 20;
pub(super) const SOURCE_FS: FilesystemId = FilesystemId([1; 32]);
pub(super) const DEST_FS: FilesystemId = FilesystemId([2; 32]);
pub(super) const VERIFIED: RegularFileEvidence = RegularFileEvidence {
	byte_len: 13,
	content_digest: [21; 32],
	required_metadata_digest: [22; 32],
};

pub(super) struct Fixture {
	pub(super) selection: Selection<'static>,
	pub(super) stage: StageReady<'static>,
}

impl Fixture {
	pub(super) fn new(image: ImagePolicy) -> Self {
		let job =
			JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
		let context = Context {
			attempt: CopyBinding::new(
				job,
				EntryId::new(5),
				RunEpoch::new(2),
				StageId::from_bytes([1; 16]),
			),
			plan: [3; 32],
			qualification: [4; 32],
			layout: [5; 32],
			lease: [6; 32],
			source_root: directory(30, SOURCE_FS),
			target: slot(31, b"public-exact"),
			stage: slot(32, b"stage-exact"),
			recovery: slot(33, b"version-exact"),
		};
		let selection = Selection {
			context,
			source: SOURCE,
			replacement: STAGE,
			incumbent: RESTORED_ORIGINAL,
			replacement_evidence: VERIFIED,
			max_replacement_bytes: 16,
			capture: grant(CAPTURE_GRANT),
			publication: grant(PUBLICATION_GRANT),
			image,
		};
		let stage = StageReady {
			context,
			object: STAGE,
			measured: VERIFIED,
			quiesced: true,
			data_flushed: true,
			independently_verified: true,
			metadata_ready: true,
			sealed: true,
		};
		Self { selection, stage }
	}

	pub(super) fn start(&self) -> Session<'static> {
		Session::start(
			self.selection,
			self.incumbent(),
			self.stage,
			self.history(head(1)),
		)
		.unwrap()
	}

	pub(super) fn history(&self, head: JournalHead) -> AdmissionHistory<'static> {
		AdmissionHistory {
			context: self.selection.context,
			replayed: head,
			current: head,
			disposition: HistoryDisposition::FreshPreIntent,
		}
	}

	pub(super) fn incumbent(&self) -> Entry<'static> {
		entry(self.selection.context.target, RESTORED_ORIGINAL)
	}

	pub(super) fn actual(&self, object: ObjectId) -> Entry<'static> {
		entry(self.selection.context.recovery, object)
	}

	pub(super) fn current(&self, grant: Grant) -> CurrentGrant<'static> {
		CurrentGrant {
			context: self.selection.context,
			grant,
			now: 1,
		}
	}

	pub(super) fn authorize_capture(&self, session: &mut Session<'static>) -> CaptureSlot<'static> {
		let intent = session.capture_intent().unwrap();
		session
			.authorize_capture(
				self.stage,
				self.current(self.selection.capture),
				ack(1, intent),
			)
			.unwrap()
	}

	pub(super) fn capture_record(&self, actual: Entry<'static>) -> CaptureRecord<'static> {
		let context = self.selection.context;
		CaptureRecord {
			capture_head: head(2),
			observed: CaptureObservation {
				context,
				barriers: CaptureBarriers {
					public: context.target.parent,
					recovery: context.recovery.parent,
				},
				retained: actual,
			},
		}
	}

	pub(super) fn capture(&self, session: &mut Session<'static>, actual: Entry<'static>) {
		let permit = self.authorize_capture(session);
		assert_eq!(permit.intent().selection, self.selection);
		assert_eq!(permit.head(), head(2));
		session
			.observe_capture(permit, CaptureOutcome::Captured(actual))
			.unwrap();
		assert_eq!(session.phase(), Phase::CaptureObserved);
		assert_eq!(session.last_captured(), Some(actual));
		assert!(session.publish_intent().is_none());
	}

	pub(super) fn verified_capture(&self) -> Session<'static> {
		let mut session = self.start();
		let incumbent = self.actual(RESTORED_ORIGINAL);
		self.capture(&mut session, incumbent);
		session
			.acknowledge_capture(ack(2, self.capture_record(incumbent)))
			.unwrap();
		session
	}

	pub(super) fn image(&self) -> ImageObservation<'static> {
		ImageObservation {
			captured: self.actual(RESTORED_ORIGINAL),
			read: self.current(grant(IMAGE_READ_GRANT)),
			create: self.current(grant(IMAGE_CREATE_GRANT)),
			image: IMAGE,
			original: VERIFIED,
			measured: VERIFIED,
			stable_view: true,
			durably_retained: true,
		}
	}

	pub(super) fn publication_ready(
		&self,
		intent: PublishIntent<'static>,
	) -> ReadyForPublication<'static> {
		ReadyForPublication {
			stage: self.stage,
			retained: intent.captured,
			retained_image: intent.image,
		}
	}

	pub(super) fn authorize_publication(
		&self,
		session: &mut Session<'static>,
	) -> PublishStage<'static> {
		let intent = session.publish_intent().unwrap();
		let permit = session
			.authorize_publication(
				self.publication_ready(intent),
				self.current(self.selection.publication),
				ack(3, intent),
			)
			.unwrap();
		assert_eq!(permit.intent(), intent);
		assert_eq!(permit.head(), head(4));
		permit
	}
}

pub(super) fn entry(slot: Slot<'static>, object: ObjectId) -> Entry<'static> {
	Entry {
		slot,
		object,
		kind: EntryKind::Regular,
	}
}

pub(super) fn directory(label: u8, filesystem: FilesystemId) -> Directory {
	Directory {
		id: ObjectId([label; 32]),
		filesystem,
	}
}

pub(super) fn slot(id: u8, name: &'static [u8]) -> Slot<'static> {
	Slot {
		parent: directory(id, DEST_FS),
		name: UnixComponent::new(name).unwrap(),
	}
}

pub(super) fn grant(label: u8) -> Grant {
	Grant {
		id: [label; 32],
		revision: NonZeroU64::MIN,
		expires_before: NonZeroU64::new(50).unwrap(),
	}
}

pub(super) fn head(position: u8) -> JournalHead {
	JournalHead {
		sequence: u64::from(position),
		digest: [position; 32],
	}
}

pub(super) fn ack<R>(previous: u8, record: R) -> Durable<R> {
	Durable {
		previous: head(previous),
		current: head(previous + 1),
		record,
	}
}

pub(super) fn independent_image() -> ImagePolicy {
	ImagePolicy::IndependentImage {
		read: grant(IMAGE_READ_GRANT),
		create: grant(IMAGE_CREATE_GRANT),
		max_bytes: VERIFIED.byte_len,
	}
}

pub(super) fn terminal(session: &mut Session<'static>, expected: Phase) {
	assert_eq!(session.phase(), expected);
	assert!(session.capture_intent().is_none());
	assert!(session.publish_intent().is_none());
	session.interrupt();
	assert_eq!(session.phase(), expected);
}
