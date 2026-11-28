use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_endpoint::linux_apply::{ApplyRecord, ApplyRole, ApplyStep, PublishedFacts};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	LinuxFileIdentity, MAX_OWNER_BYTES, MAX_RANGE_CHECKPOINTS, MAX_RANGE_PAGE_BYTES, OwnerDigest,
	OwnerTimestamp,
};
use exacopy_transfer::linux::{MAX_LOCAL_COPY_PLAN_BYTES, MAX_PUBLIC_APPLY_RECEIPT_BYTES};

use super::{ClockSample, GrantClock, LocalApplyGrantError, QualificationWindow};

pub(super) struct GrantState {
	phase: GrantPhase,
	retired: Option<LocalApplyGrantError>,
	clock: GrantClock,
}

impl GrantState {
	pub(super) const fn new(clock: GrantClock) -> Self {
		Self {
			phase: GrantPhase::Issued,
			retired: None,
			clock,
		}
	}

	pub(super) fn retire(&mut self, cause: LocalApplyGrantError) {
		self.retired.get_or_insert(cause);
	}

	pub(super) fn claim(
		&mut self,
		matches: bool,
		sample: Result<ClockSample, LocalApplyGrantError>,
	) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		if !matches!(self.phase, GrantPhase::Issued) {
			return Err(LocalApplyGrantError::Spent);
		}
		self.phase = GrantPhase::Claimed;
		if !matches {
			self.retire(LocalApplyGrantError::Scope);
			return Err(LocalApplyGrantError::Scope);
		}
		self.observe(sample)
	}

	pub(super) fn qualify(
		&mut self,
		matches: bool,
		sample: Result<ClockSample, LocalApplyGrantError>,
		window: QualificationWindow,
	) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		self.ensure_live()?;
		if !matches!(self.phase, GrantPhase::Claimed) {
			return Err(LocalApplyGrantError::Phase);
		}
		if !matches {
			self.retire(LocalApplyGrantError::Scope);
			return Err(LocalApplyGrantError::Scope);
		}
		let observed = sample.and_then(|sample| self.clock.tighten(sample, window));
		let utc = self.record_clock_result(observed)?;
		self.phase = GrantPhase::Qualified;
		Ok(utc)
	}

	pub(super) fn observe(
		&mut self,
		sample: Result<ClockSample, LocalApplyGrantError>,
	) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		self.ensure_live()?;
		let observed = sample.and_then(|sample| self.clock.observe(sample));
		self.record_clock_result(observed)
	}

	fn ensure_live(&self) -> Result<(), LocalApplyGrantError> {
		match self.retired {
			Some(cause) => Err(cause),
			None => Ok(()),
		}
	}

	fn record_clock_result(
		&mut self,
		observed: Result<OwnerTimestamp, LocalApplyGrantError>,
	) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		if let Err(cause) = observed {
			self.retire(cause);
		}
		observed
	}
}

#[derive(Clone, Copy)]
enum GrantPhase {
	Issued,
	Claimed,
	Qualified,
	Bootstrap,
	Owner(OwnerDigest),
	Prepared(OwnerDigest),
	Stage(StageFacts),
	Copying(StageFacts),
	Sealed(StageFacts),
	Verified(StageFacts),
	Metadata(StageFacts),
	IntentStarted(StageFacts),
	RenameReady(StageFacts, ChainHead),
	RenameStarted(ExpectedSettlement),
	Settled,
	Observed,
	Durable,
	CommitStarted,
}

#[derive(Clone, Copy)]
struct StageFacts {
	owner: OwnerDigest,
	identity: LinuxFileIdentity,
}

#[derive(Clone, Copy)]
pub(super) struct ExpectedSettlement {
	pub(super) target: JobFileIdentity,
	pub(super) stage_directory: JobFileIdentity,
	pub(super) destination: JobFileIdentity,
}

impl ExpectedSettlement {
	fn matches(self, observed: PublishedFacts) -> bool {
		self.target == observed.target
			&& self.stage_directory == observed.stage_directory
			&& self.destination == observed.destination
	}
}

impl GrantState {
	pub(super) fn bind_owner(
		&mut self,
		owner: OwnerDigest,
		sample: Result<ClockSample, LocalApplyGrantError>,
	) -> Result<(), LocalApplyGrantError> {
		self.observe(sample)?;
		if !matches!(self.phase, GrantPhase::Bootstrap) {
			return Err(LocalApplyGrantError::Phase);
		}
		if owner.as_bytes() == &[0; 32] {
			return Err(LocalApplyGrantError::Scope);
		}
		self.phase = GrantPhase::Owner(owner);
		Ok(())
	}

	pub(super) fn bind_stage(
		&mut self,
		matches: bool,
		identity: LinuxFileIdentity,
		sample: Result<ClockSample, LocalApplyGrantError>,
	) -> Result<(), LocalApplyGrantError> {
		self.observe(sample)?;
		let GrantPhase::Prepared(owner) = self.phase else {
			return Err(LocalApplyGrantError::Phase);
		};
		if !matches {
			return Err(LocalApplyGrantError::Scope);
		}
		self.phase = GrantPhase::Stage(StageFacts { owner, identity });
		Ok(())
	}

	pub(super) fn bind_intent(
		&mut self,
		matches: bool,
		owner: OwnerDigest,
		head: ChainHead,
		sample: Result<ClockSample, LocalApplyGrantError>,
	) -> Result<(), LocalApplyGrantError> {
		self.observe(sample)?;
		let GrantPhase::IntentStarted(stage) = self.phase else {
			return Err(LocalApplyGrantError::Phase);
		};
		if !matches || stage.owner != owner || head == ChainHead::start() {
			return Err(LocalApplyGrantError::Scope);
		}
		self.phase = GrantPhase::RenameReady(stage, head);
		Ok(())
	}

	pub(super) fn enter_rename(
		&mut self,
		matches: bool,
		owner: OwnerDigest,
		head: ChainHead,
		facts: ExpectedSettlement,
		sample: Result<ClockSample, LocalApplyGrantError>,
	) -> Result<(), LocalApplyGrantError> {
		self.observe(sample)?;
		let GrantPhase::RenameReady(stage, current) = self.phase else {
			return Err(LocalApplyGrantError::Spent);
		};
		if !matches
			|| stage.owner != owner
			|| head != current
			|| journal_identity(facts.target) != stage.identity
		{
			return Err(LocalApplyGrantError::Scope);
		}
		self.phase = GrantPhase::RenameStarted(facts);
		Ok(())
	}

	pub(super) fn bind_settled(
		&mut self,
		facts: PublishedFacts,
	) -> Result<(), LocalApplyGrantError> {
		// Settlement is an observation of the already submitted native operation.
		let GrantPhase::RenameStarted(expected) = self.phase else {
			return Err(LocalApplyGrantError::Phase);
		};
		if !expected.matches(facts) {
			return Err(LocalApplyGrantError::Scope);
		}
		self.phase = GrantPhase::Settled;
		Ok(())
	}

	pub(super) fn enter(
		&mut self,
		step: ApplyStep,
		extent: u64,
		buffer: u64,
		sample: Result<ClockSample, LocalApplyGrantError>,
	) -> Result<(), LocalApplyGrantError> {
		self.observe(sample)?;
		self.phase = self.phase.admit(step, extent, buffer)?;
		Ok(())
	}
}

impl GrantPhase {
	fn admit(
		self,
		step: ApplyStep,
		extent: u64,
		buffer: u64,
	) -> Result<Self, LocalApplyGrantError> {
		use ApplyRecord as Record;
		use ApplyRole as Role;
		use ApplyStep::{
			Append, Create, SetStageExtent, SetStagePermissions, SetStageTimes, Sync, Write,
		};

		let phase = match (self, step) {
			(Self::Qualified, Create(Role::Job)) => Self::Bootstrap,
			(
				Self::Bootstrap,
				Create(Role::Owner | Role::PrivatePlan) | Sync(Role::Owner | Role::PrivatePlan),
			) => self,
			(Self::Bootstrap, Write(Role::Owner, offset, count))
				if bounded(offset, count, MAX_OWNER_BYTES as u64) =>
			{
				self
			}
			(Self::Bootstrap, Write(Role::PrivatePlan, offset, count))
				if bounded(offset, count, MAX_LOCAL_COPY_PLAN_BYTES as u64) =>
			{
				self
			}
			(
				Self::Bootstrap | Self::Owner(_),
				Create(Role::JournalDirectory | Role::FirstSegment)
				| Sync(Role::JournalDirectory | Role::Job | Role::Destination),
			) => self,
			(Self::Owner(owner), Append(Record::Prepared)) => Self::Prepared(owner),
			(
				Self::Prepared(_),
				Create(Role::StageDirectory | Role::CheckpointDirectory | Role::Stage)
				| Sync(Role::Job | Role::StageDirectory | Role::CheckpointDirectory),
			) => self,
			(Self::Stage(stage), Append(Record::Entry)) => Self::Copying(stage),
			(Self::Copying(_), Write(Role::Stage, offset, count))
				if bounded(offset, count, extent)
					&& count <= MAX_SCRATCH_BYTES
					&& u64::try_from(count).is_ok_and(|count| count <= buffer) =>
			{
				self
			}
			(Self::Copying(_), SetStageExtent(length)) if length == extent => self,
			(
				Self::Copying(_),
				SetStagePermissions
				| SetStageTimes
				| Sync(Role::Stage | Role::StageDirectory | Role::CheckpointDirectory)
				| Append(Record::Range),
			) => self,
			(
				Self::Copying(_),
				Create(Role::CheckpointPage(ordinal)) | Sync(Role::CheckpointPage(ordinal)),
			) if (1..=MAX_RANGE_CHECKPOINTS).contains(&ordinal) => self,
			(Self::Copying(_), Write(Role::CheckpointPage(ordinal), offset, count))
				if (1..=MAX_RANGE_CHECKPOINTS).contains(&ordinal)
					&& bounded(offset, count, MAX_RANGE_PAGE_BYTES as u64) =>
			{
				self
			}
			(Self::Copying(stage), Append(Record::Seal)) => Self::Sealed(stage),
			(Self::Sealed(stage), Append(Record::Verification)) => Self::Verified(stage),
			(Self::Verified(stage), Append(Record::Metadata)) => Self::Metadata(stage),
			(Self::Metadata(stage), Append(Record::Intent)) => Self::IntentStarted(stage),
			(Self::Settled, Append(Record::Observation)) => Self::Observed,
			(Self::Observed, Append(Record::Durability)) => Self::Durable,
			(
				Self::Durable,
				Create(Role::ReceiptDirectory | Role::Receipt)
				| Sync(Role::Receipt | Role::ReceiptDirectory | Role::Job),
			) => self,
			(Self::Durable, Write(Role::Receipt, offset, count))
				if bounded(offset, count, MAX_PUBLIC_APPLY_RECEIPT_BYTES as u64) =>
			{
				self
			}
			(Self::Durable, Append(Record::ReceiptCommit)) => Self::CommitStarted,
			_ => return Err(LocalApplyGrantError::Phase),
		};
		Ok(phase)
	}
}

fn bounded(offset: u64, count: usize, maximum: u64) -> bool {
	count != 0
		&& u64::try_from(count)
			.ok()
			.and_then(|count| offset.checked_add(count))
			.is_some_and(|end| end <= maximum)
}

pub(super) fn journal_identity(native: JobFileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(native.device, native.inode)
}
