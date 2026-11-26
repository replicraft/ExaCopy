use std::num::NonZeroU64;

use exacopy_journal::DurableJournal;
use exacopy_journal::frame::{ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameReader};
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationReplay;
use exacopy_journal::remote_download::replay::{MAX_REMOTE_REPLAY_ATTEMPTS, RemoteReplayBoundary};
use exacopy_journal::remote_download::{
	RemoteDownloadBody as Body, RemoteDownloadContext, RemoteDownloadOwnerRecord,
	RemoteDownloadRecord, RemoteEpochs, RemoteSourceObservation, RemoteUncertainBoundary,
};
use exacopy_platform::linux::{
	FileIdentity, FreshRecoveryStage, LinuxJournalSegment, RecoveryFile, RecoveryWriteLease,
	WriteStage,
};

use super::super::remote_stage::{PrefixBarrier, PrefixScope};
use super::admission::RemoteActivation;
use super::lease::{CheckedCandidate, PreservedCapture, check_current};
use super::{Error, binding, component, next_epochs, record_identity};

mod append;
mod checkpoints;
mod finalization;
mod retry;

pub(super) use append::{append_payload_admitted, append_record_admitted};
use append::{check_frame, make_record};
pub(in crate::assembly::linux) use finalization::IntentReadback;

use checkpoints::CheckpointLedger;

pub(super) fn context(owner: &RemoteDownloadOwnerRecord) -> RemoteDownloadContext {
	let manifest = owner.manifest();
	RemoteDownloadContext {
		owner: owner.digest(),
		job: manifest.job,
		entry: manifest.scope.entry,
	}
}

pub(in crate::assembly::linux) struct RemoteJobJournal<'lease> {
	writer: Option<DurableJournal<LinuxJournalSegment<'lease>>>,
	lease: &'lease RecoveryWriteLease<'lease>,
	owner: &'lease RemoteDownloadOwnerRecord,
	owner_file: &'lease RecoveryFile,
	segment: RecoveryFile,
	directory: FileIdentity,
	boundary: RemoteReplayBoundary,
	spent: Vec<SpentAllocation>,
	stages: Vec<exacopy_journal::LinuxFileIdentity>,
	active: Option<Attempt>,
	activation: RemoteActivation<'lease>,
	preserved_capture: &'lease [PreservedCapture],
}

struct SpentAllocation {
	name: Box<[u8]>,
	nonce: [u8; 16],
	epochs: RemoteEpochs,
}

#[derive(Clone, Copy)]
struct Allocation {
	head: ChainHead,
	epochs: RemoteEpochs,
	nonce: [u8; 16],
	source: RemoteSourceObservation,
}

impl Allocation {
	fn new(
		head: ChainHead,
		epochs: RemoteEpochs,
		nonce: [u8; 16],
		source: RemoteSourceObservation,
	) -> Self {
		Self {
			head,
			epochs,
			nonce,
			source,
		}
	}
}

struct Prepared {
	allocation: Allocation,
	head: ChainHead,
	file: FileIdentity,
	ordinal: u16,
	covered: u64,
}

enum Attempt {
	Allocated(Allocation),
	Prepared(Prepared),
}

pub(super) struct WriterStart<'lease> {
	pub(super) segment: RecoveryFile,
	pub(in crate::assembly::linux) directory: FileIdentity,
	pub(super) activation: RemoteActivation<'lease>,
	pub(super) preserved_capture: &'lease [PreservedCapture],
}

impl<'lease> RemoteJobJournal<'lease> {
	pub(super) fn open(
		writer: DurableJournal<LinuxJournalSegment<'lease>>,
		lease: &'lease RecoveryWriteLease<'lease>,
		owner: &'lease RemoteDownloadOwnerRecord,
		owner_file: &'lease RecoveryFile,
		replay: &RemoteFinalizationReplay<'_>,
		start: WriterStart<'lease>,
	) -> Self {
		let spent = replay
			.attempts()
			.iter()
			.map(|attempt| SpentAllocation {
				name: attempt.name().into(),
				nonce: *attempt.nonce(),
				epochs: attempt.epochs(),
			})
			.collect();
		let stages = replay
			.attempts()
			.iter()
			.filter_map(|attempt| attempt.prepared().map(|stage| stage.file))
			.collect();
		Self {
			writer: Some(writer),
			lease,
			owner,
			owner_file,
			segment: start.segment,
			directory: start.directory,
			boundary: replay.boundary(),
			spent,
			stages,
			// A recovered attempt is never reopened for writing.
			active: None,
			activation: start.activation,
			preserved_capture: start.preserved_capture,
		}
	}

	pub(in crate::assembly::linux) fn allocate<'stage>(
		&mut self,
		candidate: &'stage CheckedCandidate<'stage>,
		source_epoch: NonZeroU64,
		observation: RemoteSourceObservation,
		nonce: [u8; 16],
	) -> Result<AllocatedStage<'stage>, Error>
	where
		'lease: 'stage,
	{
		if self.writer.is_none() {
			return Err(Error::Stopped);
		}
		self.activation.recheck()?;
		let previous = self.spent.last().map(|attempt| attempt.epochs);
		let next = next_epochs(previous, source_epoch)?;
		let name = candidate.name;
		let scope = &self.owner.manifest().scope;
		if observation.length().get() > scope.maximum_extent.get()
			|| nonce == [0; 16]
			|| self.spent.len() >= MAX_REMOTE_REPLAY_ATTEMPTS
			|| self
				.spent
				.iter()
				.any(|item| item.name.as_ref() == name.as_bytes() || item.nonce == nonce)
		{
			return Err(Error::Attempt);
		}
		self.check_preserved_capture()?;
		let factory = self
			.lease
			.prepare_fresh_stage(&candidate.inventory, self.directory)?;
		let head = self.append(Body::StageAllocated {
			previous,
			next,
			name,
			nonce,
			source: observation,
		})?;
		let allocation = Allocation::new(head, next, nonce, observation);
		self.active = Some(Attempt::Allocated(allocation));
		self.spent.push(SpentAllocation {
			name: name.as_bytes().into(),
			nonce,
			epochs: next,
		});
		Ok(AllocatedStage {
			factory,
			allocation,
			name,
			target: component(scope.destination.target())?,
			context: context(self.owner),
		})
	}

	fn check_preserved_capture(&self) -> Result<(), Error> {
		PreservedCapture::check_all(
			self.preserved_capture,
			self.lease.job(),
			component(self.owner.manifest().scope.destination.target())?,
			record_identity(self.directory),
		)
	}

	fn prepared(&mut self, allocation: Allocation, file: FileIdentity) -> Result<ChainHead, Error> {
		if !matches!(self.active, Some(Attempt::Allocated(current)) if current.head == allocation.head)
			|| self.boundary.head != allocation.head
			|| self.stages.contains(&record_identity(file))
		{
			return Err(Error::Binding);
		}
		let head = self.append(Body::EntryPrepared {
			allocation: allocation.head,
			epochs: allocation.epochs,
			nonce: allocation.nonce,
			stage_directory: record_identity(self.directory),
			stage: record_identity(file),
		})?;
		self.stages.push(record_identity(file));
		self.active = Some(Attempt::Prepared(Prepared {
			allocation,
			head,
			file,
			ordinal: 0,
			covered: 0,
		}));
		Ok(head)
	}

	pub(in crate::assembly::linux) fn checkpoints<'journal>(
		&'journal mut self,
		barrier: &'journal PrefixBarrier,
	) -> CheckpointLedger<'journal, 'lease> {
		CheckpointLedger::new(self, barrier)
	}

	fn append(&mut self, body: Body<'_>) -> Result<ChainHead, Error> {
		let mut writer = self.writer.take().ok_or(Error::Stopped)?;
		check_current(
			self.lease.job(),
			self.owner_file,
			self.segment.identity(),
			self.boundary.offset,
		)?;
		self.segment.recheck_observation()?;
		let previous = self.boundary;
		let candidate =
			append_record_admitted(&mut writer, previous, context(self.owner), body, || {
				if matches!(body, Body::FailureRecorded { .. }) {
					Ok(None)
				} else {
					self.activation
						.enter_effect()
						.map(Some)
						.map_err(std::io::Error::other)
				}
			})?;
		let current = check_current(
			self.lease.job(),
			self.owner_file,
			self.segment.identity(),
			candidate.offset,
		)?;
		verify_readback(&current, previous, candidate, context(self.owner), body)?;
		self.boundary = candidate;
		self.segment = current;
		self.writer = Some(writer);
		Ok(candidate.head)
	}

	pub(in crate::assembly::linux) fn record_failure(
		&mut self,
		boundary: RemoteUncertainBoundary,
	) -> Result<(), Error> {
		let (attempt, epochs) = match (&self.active, boundary) {
			(Some(Attempt::Allocated(allocation)), RemoteUncertainBoundary::Creation) => {
				(allocation.head, allocation.epochs)
			}
			(
				Some(Attempt::Prepared(active)),
				RemoteUncertainBoundary::StageBarrier | RemoteUncertainBoundary::TerminalSource,
			) => (active.head, active.allocation.epochs),
			_ => return Err(Error::Binding),
		};
		self.append(Body::FailureRecorded {
			attempt,
			epochs,
			boundary,
		})?;
		self.writer = None;
		Ok(())
	}
}

pub(in crate::assembly::linux) struct AllocatedStage<'lease> {
	factory: FreshRecoveryStage<'lease>,
	allocation: Allocation,
	name: exacopy_endpoint::UnixComponent<'lease>,
	target: exacopy_endpoint::UnixComponent<'lease>,
	context: RemoteDownloadContext,
}

impl AllocatedStage<'_> {
	pub(in crate::assembly::linux) fn create<'stage>(
		&'stage mut self,
		journal: &mut RemoteJobJournal<'_>,
	) -> Result<BoundWriter<'stage>, Error> {
		self.create_with(journal, || {})
	}

	#[cfg(test)]
	pub(in crate::assembly::linux) fn create_with_fault<'stage>(
		&'stage mut self,
		journal: &mut RemoteJobJournal<'_>,
		after_create: impl FnOnce(),
	) -> Result<BoundWriter<'stage>, Error> {
		self.create_with(journal, after_create)
	}

	fn create_with<'stage>(
		&'stage mut self,
		journal: &mut RemoteJobJournal<'_>,
		after_create: impl FnOnce(),
	) -> Result<BoundWriter<'stage>, Error> {
		if context(journal.owner) != self.context
			|| journal.boundary.head != self.allocation.head
			|| journal.writer.is_none()
		{
			return Err(Error::Binding);
		}
		let copy_binding = binding(self.context, self.allocation.epochs, self.allocation.nonce)?;
		journal.activation.recheck()?;
		journal.check_preserved_capture()?;
		let result = self.create_bound(journal, copy_binding, after_create);
		if result.is_err() {
			// Once native creation starts, a failed observation can leave an orphan.
			journal.writer = None;
		}
		result
	}

	fn create_bound<'stage>(
		&'stage mut self,
		journal: &mut RemoteJobJournal<'_>,
		copy_binding: exacopy_model::CopyBinding,
		after_create: impl FnOnce(),
	) -> Result<BoundWriter<'stage>, Error> {
		let enter = || {
			journal
				.activation
				.enter_effect()
				.map_err(std::io::Error::other)
		};
		let mut writer = self.factory.create_writer_admitted(copy_binding, enter)?;
		after_create();
		writer.flush_admitted(enter)?;
		let observed = journal.lease.job().inventory(self.name, self.target)?;
		let file = observed.stage().ok_or(Error::UnknownStage)?;
		if observed.stage_directory_identity() != Some(journal.directory)
			|| observed.target().is_some()
			|| file.identity() != writer.identity()
			|| !file.is_empty()
		{
			return Err(Error::Binding);
		}
		let prepared = journal.prepared(self.allocation, file.identity())?;
		Ok(BoundWriter {
			prefix_scope: PrefixScope {
				job: journal.lease.job().identity(),
				prepared,
				source: exacopy_transfer::remote_capture::SourceEpoch::new(
					self.allocation.epochs.source,
				),
				stage: file.identity(),
			},
			writer,
			name: self.name,
			target: self.target,
			directory: journal.directory,
			length: self.allocation.source.length().get(),
		})
	}
}

pub(in crate::assembly::linux) struct BoundWriter<'stage> {
	pub(in crate::assembly::linux) prefix_scope: PrefixScope,
	pub(in crate::assembly::linux) writer: WriteStage<'stage>,
	pub(in crate::assembly::linux) name: exacopy_endpoint::UnixComponent<'stage>,
	pub(in crate::assembly::linux) target: exacopy_endpoint::UnixComponent<'stage>,
	pub(in crate::assembly::linux) directory: FileIdentity,
	pub(in crate::assembly::linux) length: u64,
}

pub(super) fn verify_readback(
	current: &RecoveryFile,
	previous: RemoteReplayBoundary,
	expected: RemoteReplayBoundary,
	context: RemoteDownloadContext,
	body: Body<'_>,
) -> Result<Frame, Error> {
	let frame = readback_frame(
		current,
		previous,
		expected,
		exacopy_journal::remote_download::MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES,
	)?;
	check_frame(
		&frame,
		previous.head,
		make_record(previous.head, context, body)?,
	)?;
	Ok(frame)
}

pub(super) fn readback_frame(
	current: &RecoveryFile,
	previous: RemoteReplayBoundary,
	expected: RemoteReplayBoundary,
	payload_limit: usize,
) -> Result<Frame, Error> {
	let max_width = FRAME_OVERHEAD_BYTES
		.checked_add(payload_limit)
		.ok_or(Error::Binding)?;
	let width = expected
		.offset
		.checked_sub(previous.offset)
		.and_then(|width| usize::try_from(width).ok())
		.filter(|&width| width <= max_width)
		.ok_or(Error::Binding)?;
	let mut bytes = vec![0; width];
	current.read_exact_at(previous.offset, &mut bytes)?;
	current.check_logical_eof()?;
	current.recheck_observation()?;
	let mut frames = FrameReader::new(bytes.as_slice(), previous.head);
	let frame = frames.next_frame()?.ok_or(Error::Binding)?;
	if previous.head.sequence().checked_add(1) != Some(frame.head().sequence())
		|| frame.head() != expected.head
		|| frames.next_frame()?.is_some()
	{
		return Err(Error::Binding);
	}
	Ok(frame)
}
