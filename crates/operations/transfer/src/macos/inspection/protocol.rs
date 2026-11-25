use std::io::{self, BufReader};
use std::num::NonZeroU32;

use exacopy_content::ContentDigest;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DarwinEntryPrepared, DarwinPreparedError, DarwinStageObservation, MAX_OWNER_BYTES, OwnerError,
};

use crate::macos::job::STAGE_PAYLOAD;
use crate::macos::plan::{DarwinCopyPlan, DarwinCopyPlanError, MAX_DARWIN_COPY_PLAN_BYTES};
use crate::macos::receipt::MAX_DARWIN_COPY_RECEIPT_BYTES;
use crate::macos::replay::{
	DarwinJournalReplay, DarwinReplayAuthority, DarwinReplayError, DarwinReplayStatus,
	replay_journal,
};

use super::capabilities::{InspectionInventory, InspectionJob, InspectionRecord, ObservationError};
use super::readback::{self, ReadBackError};
use super::{DarwinInspectionAuthority, DarwinReceiptArtifact};

#[derive(Debug, Clone, Copy)]
pub(super) enum RecordKind {
	Plan,
	Owner,
	Receipt,
}

#[derive(Debug)]
pub(super) enum ProtocolError<E> {
	Platform(E),
	Identity(OwnerError),
	ArtifactTooLarge {
		artifact: RecordKind,
		limit: usize,
	},
	Read {
		artifact: RecordKind,
		error: std::io::Error,
	},
	Plan(DarwinCopyPlanError),
	PlanBinding,
	Preparation(DarwinPreparedError),
	Replay(DarwinReplayError),
	StageReadBack(ReadBackError<E>),
}

impl<E> From<OwnerError> for ProtocolError<E> {
	fn from(error: OwnerError) -> Self {
		Self::Identity(error)
	}
}

impl<E> From<ObservationError<E>> for ProtocolError<E> {
	fn from(error: ObservationError<E>) -> Self {
		match error {
			ObservationError::Platform(error) => Self::Platform(error),
			ObservationError::Identity(error) => Self::Identity(error),
		}
	}
}

pub(super) struct Inspection<S> {
	pub(super) plan_bytes: Vec<u8>,
	pub(super) replay: DarwinJournalReplay,
	pub(super) receipt: DarwinReceiptArtifact,
	pub(super) namespace: S,
}

pub(super) trait InspectStage<E> {
	type Evidence;

	fn inspect(
		self,
		replay: &DarwinJournalReplay,
		prepared: Option<DarwinStageObservation<'_>>,
		names: &impl InspectionInventory<Error = E>,
	) -> Result<Self::Evidence, ReadBackError<E>>;
}

pub(super) struct NamespaceOnly;

impl<E> InspectStage<E> for NamespaceOnly {
	type Evidence = ();

	fn inspect(
		self,
		_replay: &DarwinJournalReplay,
		_prepared: Option<DarwinStageObservation<'_>>,
		_names: &impl InspectionInventory<Error = E>,
	) -> Result<(), ReadBackError<E>> {
		Ok(())
	}
}

pub(super) struct StageReadBack<'scratch>(pub(super) &'scratch mut [u8]);

impl<E> InspectStage<E> for StageReadBack<'_> {
	type Evidence = ContentDigest;

	fn inspect(
		self,
		replay: &DarwinJournalReplay,
		prepared: Option<DarwinStageObservation<'_>>,
		names: &impl InspectionInventory<Error = E>,
	) -> Result<ContentDigest, ReadBackError<E>> {
		readback::verify(replay, prepared, names, self.0)
	}
}

type InspectionResult<J, T> = Result<
	(Inspection<<J as InspectionJob>::Snapshot>, T),
	ProtocolError<<J as InspectionJob>::Error>,
>;

pub(super) fn inspect<J: InspectionJob, T>(
	job: &J,
	authority: DarwinInspectionAuthority<'_>,
	stage: impl InspectStage<J::Error, Evidence = T>,
) -> InspectionResult<J, T> {
	let plan_bytes = read_record(
		job.open_plan().map_err(ProtocolError::Platform)?,
		RecordKind::Plan,
		MAX_DARWIN_COPY_PLAN_BYTES,
	)?;
	let plan =
		DarwinCopyPlan::decode(&plan_bytes, authority.profile).map_err(ProtocolError::Plan)?;
	let destination = plan.destination();
	if !job.matches_job(plan.attempt().job)
		|| destination.root_id != authority.destination_root
		|| job.observe_destination()? != destination.root_identity
	{
		return Err(ProtocolError::PlanBinding);
	}
	let owner = read_record(
		job.open_owner().map_err(ProtocolError::Platform)?,
		RecordKind::Owner,
		MAX_OWNER_BYTES,
	)?;
	let mut segment = job.open_first_segment().map_err(ProtocolError::Platform)?;
	let replay = replay_journal(
		BufReader::new(&mut segment),
		&plan,
		&owner,
		DarwinReplayAuthority {
			profile: authority.profile,
			key: authority.key,
			state_root: job.identity()?,
			state_root_uid: NonZeroU32::new(job.owner_uid()).ok_or(OwnerError::InvalidOwnerUid)?,
		},
	)
	.map_err(ProtocolError::Replay)?;
	let prepared = replay
		.frame(FrameKind::EntryPrepared)
		.map(DarwinEntryPrepared::from_frame)
		.transpose()
		.map_err(ProtocolError::Preparation)?
		.map(|entry| entry.preparation().stage);
	let stage_name = match prepared {
		Some(stage) => stage.component,
		None => UnixComponent::new(STAGE_PAYLOAD)
			.map_err(DarwinPreparedError::InvalidComponent)
			.map_err(ProtocolError::Preparation)?,
	};
	let names = job
		.inventory(stage_name, destination.component)
		.map_err(ProtocolError::Platform)?;
	let receipt = match job.open_receipt().map_err(ProtocolError::Platform)? {
		None => DarwinReceiptArtifact::Missing,
		Some(record) if replay.status() == DarwinReplayStatus::Complete => {
			let bytes = read_record(record, RecordKind::Receipt, MAX_DARWIN_COPY_RECEIPT_BYTES)?;
			let receipt = replay
				.validate_receipt(&plan, &bytes)
				.map_err(ProtocolError::Replay)?;
			DarwinReceiptArtifact::MatchesCommitment(receipt.digest())
		}
		Some(_) => DarwinReceiptArtifact::PresentUncommitted,
	};
	let observed = stage
		.inspect(&replay, prepared, &names)
		.map_err(ProtocolError::StageReadBack)?;
	names.revalidate().map_err(ProtocolError::Platform)?;
	segment.revalidate().map_err(ProtocolError::Platform)?;
	let namespace = names.snapshot();
	drop(names);
	Ok((
		Inspection {
			plan_bytes,
			replay,
			receipt,
			namespace,
		},
		observed,
	))
}

fn read_record<R: InspectionRecord>(
	mut record: R,
	artifact: RecordKind,
	limit: usize,
) -> Result<Vec<u8>, ProtocolError<R::Error>> {
	let length = usize::try_from(record.length())
		.ok()
		.filter(|&length| length <= limit)
		.ok_or(ProtocolError::ArtifactTooLarge { artifact, limit })?;
	let mut buffer = vec![0; length];
	record
		.read_exact(&mut buffer)
		.map_err(|error: io::Error| ProtocolError::Read { artifact, error })?;
	record.revalidate().map_err(ProtocolError::Platform)?;
	Ok(buffer)
}

#[cfg(test)]
mod tests;
