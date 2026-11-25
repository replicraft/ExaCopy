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
/// A private artifact selected for bounded decoding.
pub enum RecordKind {
	/// The canonical copy plan.
	Plan,
	/// The signed owner envelope.
	Owner,
	/// The committed copy receipt.
	Receipt,
}

#[derive(Debug)]
/// The reason held job inspection or authentication stopped.
pub enum ProtocolError<E> {
	/// The adapter could not establish the required observation.
	Platform(E),
	/// The observed identity is outside the journal's representation.
	Identity(OwnerError),
	/// The artifact exceeds its codec bound.
	ArtifactTooLarge {
		/// The private artifact being inspected.
		artifact: RecordKind,
		/// The codec's maximum supported size in bytes.
		limit: usize,
	},
	/// The bounded record read failed.
	Read {
		/// The private artifact being inspected.
		artifact: RecordKind,
		/// The underlying read error.
		error: std::io::Error,
	},
	/// The plan could not be decoded under the trusted profile.
	Plan(DarwinCopyPlanError),
	/// The observed job or destination differs from the plan.
	PlanBinding,
	/// The accepted entry did not provide a valid private stage component.
	Preparation(DarwinPreparedError),
	/// The owner, journal, or receipt failed authentication or semantic replay.
	Replay(DarwinReplayError),
	/// The requested private stage measurement failed.
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

/// Authenticated history and current checked namespace evidence.
#[derive(Debug)]
pub struct Inspection<S> {
	/// The exact canonical plan bytes authenticated by the signed owner.
	pub plan_bytes: Vec<u8>,
	/// The accepted prefix of the held first journal segment.
	pub replay: DarwinJournalReplay,
	/// The receipt artifact's association with accepted journal history.
	pub receipt: DarwinReceiptArtifact,
	/// Current namespace observations returned by the leased adapter.
	pub namespace: S,
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
