//! Records the one actual live publication outcome without re-entering authority.

use std::cell::OnceCell;
use std::io::{Cursor, Read as _};
use std::num::NonZeroU64;

use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::WitnessedPassProgress;
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	PreparedWitnessedCloseout, RemoteWitnessedReplayPhase, replay_remote_witnessed_closeout,
};
use exacopy_journal::{LinuxFileIdentity, NamespaceObservation as JournalName};
use exacopy_model::retained_prefix::Head;
use exacopy_model::witnessed_publication::{
	HeldFile, NameObservation, NativeRenameOutcome, RenameSubmission, SubmissionObservation,
};
use exacopy_platform::linux::{
	ContinuationReservationError, FileIdentity, PublishError, SourceObservation,
	WitnessObservationAppend, WitnessPublicationName, WitnessPublicationObservation,
};

use super::{LinkedPublication, SubmittedPublication, WitnessAdmissionError, model_head};

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum WitnessedObservationError {
	Journal(ContinuationReservationError<WitnessAdmissionError>),
}

impl SubmittedPublication<'_, '_, '_, '_> {
	/// Closes the exact spent rename token against its original held journal.
	/// A failure retains the physical observation and never admits another append.
	pub(in crate::assembly::linux::remote_continued) fn record_observation(
		&mut self,
	) -> Result<RemoteReplayBoundary, WitnessedObservationError> {
		let selected = OnceCell::<(PreparedWitnessedCloseout, RemoteWitnessedOutcome)>::new();
		let journal = |cause| WitnessedObservationError::Journal(cause);
		let pass = self.pass;
		let witness = self.witness;
		let intent_cut = self.intent_cut;
		let logical = &mut self.logical;

		let head = self
			.native
			.record_observation(
				|submission, physical, input| {
					let replay =
						replay_remote_witnessed_closeout(input, pass.trust, pass.selection)
							.map_err(WitnessAdmissionError::Format)?;
					if replay.issue().is_some()
						|| replay.phase()
							!= RemoteWitnessedReplayPhase::PublishIntentRequiresObservation
						|| replay.boundary() != intent_cut
						|| replay.witness() != Some(witness)
					{
						return Err(WitnessAdmissionError::Binding);
					}
					pass.budget
						.recheck_remaining(intent_cut, WitnessedPassProgress::PublishIntent)
						.map_err(|_| WitnessAdmissionError::Binding)?;
					let outcome =
						logical.observe_native(submission, model_head(intent_cut), physical)?;
					let codec = replay
						.prepare_live_observation(pass.trust, witness, outcome)
						.map_err(WitnessAdmissionError::Format)?;
					let successor = codec.successor();
					if matches!(outcome, RemoteWitnessedOutcome::Submitted(_)) {
						pass.budget
							.recheck_remaining(successor, WitnessedPassProgress::PublishedObserved)
							.map_err(|_| WitnessAdmissionError::Binding)?;
					}
					let native = WitnessObservationAppend {
						previous: model_head(codec.previous()),
						successor: model_head(successor),
						encoded: codec.encoded().to_vec(),
					};
					selected
						.set((codec, outcome))
						.map_err(|_| WitnessAdmissionError::Binding)?;
					Ok(native)
				},
				|input, proposed| {
					let (codec, outcome) = selected.get().ok_or(WitnessAdmissionError::Binding)?;
					let replay = replay_remote_witnessed_closeout(
						input.chain(Cursor::new(proposed.encoded.as_slice())),
						pass.trust,
						pass.selection,
					)
					.map_err(WitnessAdmissionError::Format)?;
					codec
						.confirms_live_observation(&replay, witness, *outcome)
						.then_some(())
						.ok_or(WitnessAdmissionError::Binding)
				},
				|input, _| {
					let (codec, outcome) = selected.get().ok_or(WitnessAdmissionError::Binding)?;
					let replay =
						replay_remote_witnessed_closeout(input, pass.trust, pass.selection)
							.map_err(WitnessAdmissionError::Format)?;
					codec
						.confirms_live_observation(&replay, witness, *outcome)
						.then_some(())
						.ok_or(WitnessAdmissionError::Binding)
				},
			)
			.map_err(journal)?;
		let (codec, _) = selected.into_inner().ok_or_else(|| {
			journal(ContinuationReservationError::SuccessorReplay(
				WitnessAdmissionError::Binding,
			))
		})?;
		if model_head(codec.successor()) != head {
			return Err(journal(ContinuationReservationError::SuccessorReplay(
				WitnessAdmissionError::Binding,
			)));
		}
		Ok(codec.successor())
	}
}

impl LinkedPublication {
	pub(super) fn observe_native(
		&mut self,
		submission: RenameSubmission,
		intent: Head,
		native: &WitnessPublicationObservation,
	) -> Result<RemoteWitnessedOutcome, WitnessAdmissionError> {
		let live = self.model.observation(intent);
		let mut names = self.model.names(true);
		let (reported, body) = match native {
			WitnessPublicationObservation::Published(stamp) => {
				names.stage = NameObservation::Absent;
				names.target = self.model_name(*stamp)?;
				(
					NativeRenameOutcome::Success,
					RemoteWitnessedOutcome::Submitted(journal_inode(stamp.identity())),
				)
			}
			WitnessPublicationObservation::Conflict(stamp) => {
				names.target = self.model_name(*stamp)?;
				(
					NativeRenameOutcome::Conflict,
					RemoteWitnessedOutcome::Conflict,
				)
			}
			WitnessPublicationObservation::Reconcile {
				submission: actual,
				names: observed,
				..
			} => {
				// Keep the actual kernel return in the native result. An
				// unconfirmed namespace cannot authorize positive model closure.
				names.stage = NameObservation::Uncertain;
				names.witness = NameObservation::Uncertain;
				names.target = NameObservation::Uncertain;
				let reported = match actual {
					Ok(()) => NativeRenameOutcome::Success,
					Err(PublishError::Conflict) => NativeRenameOutcome::Conflict,
					Err(_) => NativeRenameOutcome::Uncertain,
				};
				(
					reported,
					RemoteWitnessedOutcome::Uncertain {
						target: journal_name(observed.public_target),
						stage: journal_name(observed.private_stage),
						witness: journal_name(observed.protected_witness),
					},
				)
			}
		};
		let decision = self
			.state
			.observe_submission(submission, live, names, reported)
			.map_err(WitnessAdmissionError::Model)?;
		match (decision, body) {
			(SubmissionObservation::Published, RemoteWitnessedOutcome::Submitted(_))
			| (SubmissionObservation::Conflict, RemoteWitnessedOutcome::Conflict)
			| (SubmissionObservation::Reconcile(_), RemoteWitnessedOutcome::Uncertain { .. }) => Ok(body),
			_ => Err(WitnessAdmissionError::Binding),
		}
	}

	fn model_name(
		&self,
		stamp: SourceObservation,
	) -> Result<NameObservation, WitnessAdmissionError> {
		let id = stamp.identity();
		let inode = NonZeroU64::new(id.inode()).ok_or(WitnessAdmissionError::Binding)?;
		Ok(NameObservation::Held(HeldFile {
			identity: exacopy_model::witnessed_publication::FileIdentity {
				mount: self.model.scope.stage.mount,
				device: id.device(),
				inode,
			},
			links: stamp.link_count(),
		}))
	}
}

fn journal_inode(inode: FileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(inode.device(), inode.inode())
}

fn journal_name(observed: WitnessPublicationName) -> JournalName {
	match observed {
		WitnessPublicationName::Unobserved => JournalName::Unobserved,
		WitnessPublicationName::Absent => JournalName::Absent,
		WitnessPublicationName::Regular(stamp) => {
			JournalName::Present(journal_inode(stamp.identity()))
		}
	}
}
