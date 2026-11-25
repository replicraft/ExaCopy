use exacopy_endpoint::{UnixComponent, read_exact_at, write_all_at};
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopyPhase, CopySession, EntryId, JobId, RunEpoch, StageId,
};
use exacopy_test_support::{
	Area, DiskId, EffectError, EffectFault, EffectOperation, Entry, Failure, FileView, ObjectId,
	Rejection, Simulator, Snapshot, TransferFault, TransferOperation, WritableArea,
};

pub(super) const CONTENTS: &[u8; 6] = b"\xffab\x00cd";
pub(super) const INCUMBENT: &[u8] = b"do not modify";
pub(super) const REBOUND: &[u8] = b"unrelated stage";
const INTENT_MARKER: &[u8] = b"simulation-only evidence";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Boundary {
	StageCreate,
	SourceRead,
	StageWrite,
	DataFlush,
	Readback,
	Publish,
	DestinationFlush,
	PrivateFlush,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Script {
	Pass,
	Before(Failure),
	After(Failure),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Race {
	Absent,
	Incumbent,
	Rebound,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Case {
	pub(super) at: Boundary,
	pub(super) script: Script,
	pub(super) race: Race,
}

impl Case {
	fn effect(self, at: Boundary, storage: &mut Simulator, operation: EffectOperation) {
		if self.at == at {
			let fault = match self.script {
				Script::Pass => EffectFault::Pass,
				Script::Before(reason) => EffectFault::Before(reason),
				Script::After(reason) => EffectFault::After(reason),
			};
			storage.inject_effect(operation, fault).unwrap();
		}
	}

	fn transfer(self, at: Boundary, storage: &mut Simulator, operation: TransferOperation) {
		for fault in [TransferFault::Interrupted, TransferFault::Short(1)] {
			storage.inject_transfer(operation, fault).unwrap();
		}
		if self.at == at {
			let fault = match self.script {
				Script::Pass => TransferFault::Pass,
				Script::Before(reason) => TransferFault::Before(reason),
				Script::After(reason) => TransferFault::After {
					bytes: 2,
					failure: reason,
				},
			};
			storage.inject_transfer(operation, fault).unwrap();
		}
	}
}

struct Attempt {
	binding: CopyBinding,
	session: CopySession,
}

impl Attempt {
	fn new() -> Self {
		let mut uuid = [0; 16];
		uuid[6] = 0x70;
		uuid[8] = 0x80;
		let binding = CopyBinding::new(
			JobId::try_from_bytes(uuid).unwrap(),
			EntryId::new(1),
			RunEpoch::new(1),
			StageId::from_bytes([1; 16]),
		);
		Self {
			binding,
			session: CopySession::new(binding),
		}
	}

	fn no_effect(&mut self, event: CopyEvent) {
		assert_eq!(self.session.apply(self.binding, event).unwrap(), None);
	}

	fn no_early_intent(&mut self) {
		let phase = self.session.phase();
		assert!(
			self.session
				.apply(self.binding, CopyEvent::PublishIntentRecorded)
				.is_err(),
			"premature intent produced an effect in {phase:?}",
		);
		assert_eq!(self.session.phase(), phase);
	}
}

pub(super) struct Fixture {
	pub(super) disk: Simulator,
	source: UnixComponent<'static>,
	pub(super) stage: UnixComponent<'static>,
	intent: UnixComponent<'static>,
	pub(super) target: UnixComponent<'static>,
	pub(super) source_id: ObjectId,
	pub(super) incumbent_id: Option<ObjectId>,
	pub(super) stage_id: Option<ObjectId>,
	pub(super) rebound_id: Option<ObjectId>,
	attempt: Attempt,
}

impl Fixture {
	pub(super) fn new() -> Self {
		let mut disk = Simulator::new(DiskId::new(1));
		let source = UnixComponent::new(b"\xffsource").unwrap();
		let source_id = disk.seed_file(Area::Source, &source, CONTENTS).unwrap();
		Self {
			disk,
			source,
			stage: UnixComponent::new(b"stage").unwrap(),
			intent: UnixComponent::new(b"intent").unwrap(),
			target: UnixComponent::new(b"target").unwrap(),
			source_id,
			incumbent_id: None,
			stage_id: None,
			rebound_id: None,
			attempt: Attempt::new(),
		}
	}

	pub(super) fn phase(&self) -> CopyPhase {
		self.attempt.session.phase()
	}

	pub(super) fn copy(&mut self, case: Case) {
		self.attempt.no_early_intent();
		if self.prepare(case).is_err() {
			self.attempt.no_effect(CopyEvent::IoFailed);
		}
	}

	fn prepare(&mut self, case: Case) -> Result<(), ()> {
		case.effect(
			Boundary::StageCreate,
			&mut self.disk,
			EffectOperation::Create,
		);
		let writer = self
			.disk
			.create_stage(&self.stage, &self.target)
			.map_err(|_| ())?;
		self.stage_id = Some(writer.identity());
		let effect = self
			.attempt
			.session
			.apply(self.attempt.binding, CopyEvent::StagePrepared)
			.unwrap();
		let Some(CopyEffect::ReadSource(request)) = effect else {
			panic!("preparation did not authorize the read-only source request: {effect:?}");
		};
		assert_eq!(request.binding(), self.attempt.binding);
		self.attempt.no_early_intent();
		let reader = self.disk.open_source(&self.source).unwrap();
		let mut streamed = [0; CONTENTS.len()];
		case.transfer(
			Boundary::SourceRead,
			&mut self.disk,
			TransferOperation::Read,
		);
		read_exact_at(0, &mut streamed, |offset, buffer| {
			self.disk.read_at(&reader, offset, buffer)
		})
		.map_err(|_| ())?;
		case.transfer(
			Boundary::StageWrite,
			&mut self.disk,
			TransferOperation::Write,
		);
		write_all_at(0, &streamed, |offset, buffer| {
			self.disk.write_at(&writer, offset, buffer)
		})
		.map_err(|_| ())?;
		let stage = writer.quiesce();
		self.attempt.no_effect(CopyEvent::WritersJoined);
		self.attempt.no_early_intent();
		case.effect(
			Boundary::DataFlush,
			&mut self.disk,
			EffectOperation::FlushFile,
		);
		self.disk.flush_file(&stage).map_err(|_| ())?;
		self.attempt.no_effect(CopyEvent::DataFlushed);
		self.attempt.no_early_intent();

		let readback = self.disk.open_quiesced(&stage).unwrap();
		let mut observed = [0; CONTENTS.len()];
		case.transfer(Boundary::Readback, &mut self.disk, TransferOperation::Read);
		read_exact_at(0, &mut observed, |offset, buffer| {
			self.disk.read_at(&readback, offset, buffer)
		})
		.map_err(|_| ())?;
		assert_eq!(
			self.disk
				.read_at(&readback, CONTENTS.len() as u64, &mut [0])
				.unwrap(),
			0
		);
		assert_eq!(observed, streamed);
		self.attempt.no_effect(CopyEvent::ReadbackVerified);
		self.attempt.no_early_intent();
		// The fixture policy has no additional metadata classes.
		self.attempt.no_effect(CopyEvent::MetadataReady);
		self.attempt.no_early_intent();
		self.attempt.no_effect(CopyEvent::StageSealed);
		self.persist_intent_fixture();
		assert_eq!(
			self.disk
				.live_snapshot()
				.entry(Area::Destination, &self.target),
			None
		);

		let effect = self
			.attempt
			.session
			.apply(self.attempt.binding, CopyEvent::PublishIntentRecorded)
			.unwrap();
		let Some(CopyEffect::PublishNoClobber(permit)) = effect else {
			panic!("durable fixture intent did not authorize exclusive publication: {effect:?}");
		};
		assert_eq!(permit.binding(), self.attempt.binding);
		self.attempt.no_early_intent();
		match case.race {
			Race::Absent => {}
			Race::Incumbent => {
				self.incumbent_id = Some(
					self.disk
						.seed_file(Area::Destination, &self.target, INCUMBENT)
						.unwrap(),
				);
			}
			Race::Rebound => {
				self.rebound_id = Some(self.disk.rebind_stage(&self.stage, REBOUND).unwrap());
			}
		}
		case.effect(Boundary::Publish, &mut self.disk, EffectOperation::Publish);
		match self.disk.publish_no_clobber(stage) {
			Ok(()) => self.attempt.no_effect(CopyEvent::Published),
			Err(EffectError::Rejected(Rejection::Conflict)) => {
				self.attempt.no_effect(CopyEvent::Conflict);
				return Ok(());
			}
			Err(_) => {
				self.attempt.no_effect(CopyEvent::OutcomeUncertain);
				return Ok(());
			}
		}
		case.effect(
			Boundary::PrivateFlush,
			&mut self.disk,
			EffectOperation::FlushDirectory,
		);
		let private = self.disk.flush_directory(WritableArea::Private);
		case.effect(
			Boundary::DestinationFlush,
			&mut self.disk,
			EffectOperation::FlushDirectory,
		);
		let destination = self.disk.flush_directory(WritableArea::Destination);
		let observation = if private.is_ok() && destination.is_ok() {
			CopyEvent::DirectoryFlushed
		} else {
			CopyEvent::OutcomeUncertain
		};
		self.attempt.no_effect(observation);
		Ok(())
	}

	fn persist_intent_fixture(&mut self) {
		let intent = self.disk.create_stage(&self.intent, &self.intent).unwrap();
		write_all_at(0, INTENT_MARKER, |offset, buffer| {
			self.disk.write_at(&intent, offset, buffer)
		})
		.unwrap();
		self.disk.flush_file(&intent.quiesce()).unwrap();
		self.disk.flush_directory(WritableArea::Private).unwrap();
		assert!(self.has_stable_intent());
	}

	pub(super) fn has_stable_intent(&self) -> bool {
		let stable = self.disk.stable_snapshot();
		matches!(
			stable.entry(Area::Private, &self.intent),
			Some(Entry::File(file)) if file.bytes == INTENT_MARKER
		)
	}

	pub(super) fn file_in(
		&self,
		snapshot: &Snapshot,
		area: Area,
		identity: ObjectId,
		bytes: &[u8],
	) -> bool {
		let component = match area {
			Area::Source => &self.source,
			Area::Private => &self.stage,
			Area::Destination => &self.target,
		};
		snapshot.entry(area, component) == Some(Entry::File(FileView { identity, bytes }))
	}

	pub(super) fn valid_publication(&self, snapshot: &Snapshot) -> bool {
		self.has_stable_intent()
			&& self.stage_id.is_some_and(|stage| {
				stage != self.source_id
					&& self.file_in(snapshot, Area::Destination, stage, CONTENTS)
			})
	}
}
