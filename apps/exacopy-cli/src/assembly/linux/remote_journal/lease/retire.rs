use exacopy_journal::NamespaceObservation;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::remote_download::finalization::RemotePublishTarget;
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationPhase;
use exacopy_journal::remote_download::retirement::{
	RemoteCaptureRetired, RemoteRetirementObservation,
};

use super::{
	CheckedCandidate, Error, RemoteJobJournal, RemoteJobLease, append_payload, check_current,
	component, readback_frame, record_identity, require_live_phase,
};

impl RemoteJobLease<'_> {
	/// Retires one sealed capture and hands off its still-locked retired writer.
	pub(in crate::assembly::linux) fn retire_and_open_writer(
		&self,
		candidate: &CheckedCandidate<'_>,
	) -> Result<RemoteJobJournal<'_>, Error> {
		use RemoteFinalizationPhase as Phase;
		if !matches!(
			self.phase,
			Phase::Sealed | Phase::Verified | Phase::MetadataReady
		) {
			return Err(Error::Lifecycle {
				phase: self.phase,
				boundary: self.boundary,
				issue: None,
			});
		}
		let (current, replay) = self.checked_scan(candidate)?;
		let attempt = replay.attempts().last().ok_or(Error::UnknownStage)?;
		let prepared = attempt.prepared().ok_or(Error::UnknownStage)?;
		let stage_name = component(attempt.name())?;
		let scope = self.activation.scope;
		let target = component(scope.destination.target())?;
		let inventory = self.job().inventory(stage_name, target)?;
		let file = inventory.stage().ok_or(Error::UnknownStage)?;
		let directory = inventory
			.stage_directory_identity()
			.ok_or(Error::UnknownStage)?;
		if inventory.target().is_some()
			|| record_identity(directory) != self.stage_directory
			|| record_identity(directory) != prepared.directory
			|| record_identity(file.identity()) != prepared.file
			|| file.len() != attempt.source().length().get()
		{
			return Err(Error::UnknownStage);
		}
		file.check_logical_eof()?;
		let planned = replay.retirement_candidate(
			self.activation.grant_digest,
			RemoteRetirementObservation {
				directory: record_identity(directory),
				stage_name,
				stage: record_identity(file.identity()),
				target: RemotePublishTarget {
					root: scope.destination.root(),
					parent: record_identity(self.job().destination_identity()),
					component: target,
				},
				target_observation: NamespaceObservation::Absent,
				qualification_digest: self.activation.qualification_digest,
				grant_digest: self.activation.grant_digest,
			},
		)?;
		let expected = planned.record();
		if expected.predecessor() != self.boundary.head {
			return Err(Error::Binding);
		}
		let mut writer = self.resume_writer()?;
		inventory.recheck()?;
		candidate.inventory.recheck()?;
		current.recheck_observation()?;
		self.activation.recheck()?;
		let (declared, synced, boundary) = append_payload(
			&mut writer,
			self.boundary,
			FrameKind::RemoteCaptureRetired,
			expected.encode()?,
		)?;
		let mut updated = check_current(
			self.job(),
			&self.owner_file,
			current.identity(),
			boundary.offset,
		)?;
		let actual = readback_frame(
			&updated,
			self.boundary,
			boundary,
			exacopy_journal::remote_download::retirement::MAX_REMOTE_RETIREMENT_BYTES,
		)?;
		if declared.payload() != actual.payload()
			|| RemoteCaptureRetired::from_frame(&actual)? != expected
			|| planned.validate_synced(&synced)? != boundary.head
		{
			return Err(Error::Binding);
		}
		// The independent frame read used positional reads. Replay starts at byte zero.
		let retired = self.scan(&mut updated)?;
		require_live_phase(&retired, self.activation)?;
		if retired.phase() != Phase::Retired || retired.boundary() != boundary {
			return Err(Error::Binding);
		}
		inventory.recheck()?;
		candidate.inventory.recheck()?;
		self.activation.recheck()?;
		Ok(self.bind_writer(writer, updated, &retired, candidate.directory))
	}
}
