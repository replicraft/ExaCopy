//! Live application binding between the transfer traversal and Linux custody.

use std::cell::Cell;
use std::io::{Cursor, Read};

use exacopy_endpoint::ReadView;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::remote_download::RemoteBootstrapTrust;
use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::RemoteWitnessIntent;
use exacopy_journal::remote_download::witness::replay::{
	PreparedWitnessedCloseout, RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};
use exacopy_platform::linux::{
	ContinuationReservationError, ReservedJournalRead, StageError, WitnessPrepublicationAppend,
	WitnessPrepublicationPhase, WitnessReservationAuthority, WitnessReservationObservationError,
};
use exacopy_transfer::remote_resume::prefix::SuffixSourceObservation;
use exacopy_transfer::remote_witnessed_finalization::{
	HeldWitnessPrepublication, WitnessedAppendError, WitnessedLiveCut,
	WitnessedPrepublicationFailure, WitnessedPrepublicationRequest, WitnessedPublicationIntent,
	prepare_witnessed_publication,
};

use super::{LinkedWitnessedStage, WitnessAdmissionError, model_head, reservation_plan};

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum WitnessedAdapterError {
	Binding,
	#[cfg_attr(
		feature = "experimental-verified-prefix-resume",
		expect(dead_code, reason = "retains the exact private error cause")
	)]
	Stage(StageError),
	#[cfg_attr(
		feature = "experimental-verified-prefix-resume",
		expect(dead_code, reason = "retains the exact private error cause")
	)]
	Custody(WitnessReservationObservationError),
	#[cfg_attr(
		feature = "experimental-verified-prefix-resume",
		expect(dead_code, reason = "retains the exact private error cause")
	)]
	Admission(WitnessAdmissionError),
	#[cfg_attr(
		feature = "experimental-verified-prefix-resume",
		expect(dead_code, reason = "retains the exact private error cause")
	)]
	Journal(ContinuationReservationError<WitnessAdmissionError>),
}

impl<'view, 'lease, 'scope, 'name> LinkedWitnessedStage<'view, 'lease, 'scope, 'name> {
	pub(super) fn prepare_publication(
		self,
		scratch: &mut [u8],
	) -> Result<
		WitnessedPublicationIntent<Self>,
		Box<WitnessedPrepublicationFailure<WitnessedAdapterError>>,
	> {
		let request = WitnessedPrepublicationRequest {
			trust: self.pass.trust,
			selection: self.pass.selection,
			current: self.pass.current,
			witness: self.intent,
			budget: self.pass.budget,
		};
		prepare_witnessed_publication(request, self, scratch).map_err(Box::new)
	}

	pub(super) fn check_origin(
		&self,
		expected: WitnessedLiveCut<'_, '_>,
	) -> Result<(), WitnessedAdapterError> {
		let pass = &self.pass;
		let consent = pass.approval.commitment();
		let authority = WitnessReservationAuthority {
			qualification: *pass.current.verified().digest().as_bytes(),
			base_grant: consent.base_grant_digest,
			retention_approval: consent.approval_digest,
		};
		if !std::ptr::eq(expected.current, pass.current)
			|| !std::ptr::eq(pass.selection.qualification, pass.current.verified())
			|| expected.witness != self.intent
			|| expected.budget != pass.budget
			|| self.intent.consent() != consent
			|| self.chain.authority() != authority
			|| self.chain.qualification_facts() != pass.current.facts()
			|| self.chain.head() != model_head(expected.previous)
			|| reservation_plan(expected.budget).ok() != Some(self.chain.plan())
			|| self.chain.receipt_capacity() != u64::from(expected.budget.receipt_bytes())
			|| !self.route.matches_invocation(pass.grant)
			|| self.route.binding().source_epoch() != self.source.epoch()
		{
			return Err(WitnessedAdapterError::Binding);
		}
		Ok(())
	}
}

impl ReadView for LinkedWitnessedStage<'_, '_, '_, '_> {
	type Error = WitnessedAdapterError;

	fn length(&self) -> u64 {
		self.chain.stage().length()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.chain
			.stage()
			.recheck_observation()
			.map_err(WitnessedAdapterError::Stage)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.chain
			.stage()
			.read_exact_at(offset, bytes)
			.map_err(WitnessedAdapterError::Stage)
	}
}

impl HeldWitnessPrepublication for LinkedWitnessedStage<'_, '_, '_, '_> {
	type JournalRead<'held>
		= ReservedJournalRead<'held>
	where
		Self: 'held;

	fn source(&self) -> &SuffixSourceObservation {
		&self.source
	}

	fn check_live(&self, cut: WitnessedLiveCut<'_, '_>) -> Result<(), Self::Error> {
		self.check_origin(cut)?;
		self.chain
			.recheck_prepublication(model_head(cut.previous))
			.map_err(WitnessedAdapterError::Custody)?;
		let _guard = self
			.pass
			.approval
			.enter(self.pass.grant, self.pass.names)
			.map_err(WitnessAdmissionError::Consent)
			.map_err(WitnessedAdapterError::Admission)?;
		Ok(())
	}

	fn read_journal(&self) -> Result<Self::JournalRead<'_>, Self::Error> {
		self.chain
			.read_prepublication(self.chain.head())
			.map_err(WitnessedAdapterError::Custody)
	}

	fn check_metadata(&self) -> Result<RemoteLocalMetadata, Self::Error> {
		let stamp = self
			.chain
			.check_witnessed_metadata(self.chain.head())
			.map_err(WitnessedAdapterError::Custody)?;
		Ok(RemoteLocalMetadata {
			uid: stamp.owner(),
			gid: stamp.group(),
		})
	}

	fn append(
		&mut self,
		cut: WitnessedLiveCut<'_, '_>,
		frame: &PreparedWitnessedCloseout,
	) -> Result<(), WitnessedAppendError<Self::Error>> {
		use WitnessedAppendError::{Refused, Uncertain, Unconfirmed};

		self.check_origin(cut).map_err(Unconfirmed)?;
		if frame.previous() != cut.previous {
			return Err(Refused(WitnessedAdapterError::Binding));
		}
		let (phase, successor_phase) =
			transition(frame.kind()).ok_or(Refused(WitnessedAdapterError::Binding))?;
		let pass = self.pass;
		let intent = self.intent;
		let previous = model_head(frame.previous());
		let successor = model_head(frame.successor());
		let encoded = frame.encoded();
		let authority = self.chain.authority();
		let plan = self.chain.plan();
		let logical = &mut self.logical;
		let seal_admitted_at = Cell::new(None);
		let confirm = |input: ReservedJournalRead<'_>| {
			confirm_successor(
				input,
				pass.trust,
				pass.selection,
				intent,
				frame.successor(),
				successor_phase,
			)?;
			if frame.kind() == FrameKind::StageSealed {
				logical
					.seal(successor, seal_admitted_at.get())
					.map_err(WitnessAdmissionError::Model)?;
			}
			Ok(())
		};
		self.chain
			.append_prepublication(
				phase,
				WitnessPrepublicationAppend {
					previous,
					successor,
					encoded,
				},
				|input| {
					confirm_successor(
						input.chain(Cursor::new(encoded)),
						pass.trust,
						pass.selection,
						intent,
						frame.successor(),
						successor_phase,
					)
				},
				|native| {
					let root = pass.current.facts().ids().root;
					if native.previous != previous
						|| native.successor != successor
						|| native.plan != plan
						|| native.authority != authority
						|| native.stage != pass.names.retained
						|| native.job.device() != pass.names.job.device()
						|| native.job.inode() != pass.names.job.inode()
						|| native.destination.device() != root.device
						|| native.destination.inode() != root.inode
					{
						return Err(WitnessAdmissionError::Binding);
					}
					let guard = pass
						.approval
						.enter(pass.grant, pass.names)
						.map_err(WitnessAdmissionError::Consent)?;
					if frame.kind() == FrameKind::StageSealed {
						seal_admitted_at.set(guard.observed_wall_seconds());
					}
					Ok(guard)
				},
				confirm,
			)
			.map(|()| match frame.kind() {
				FrameKind::VerificationRecorded => self.logical.verified(successor),
				FrameKind::MetadataRecorded => self.logical.metadata(successor),
				_ => {}
			})
			.map_err(|error| match error {
				ContinuationReservationError::Bounds
				| ContinuationReservationError::Admission(WitnessAdmissionError::Consent(_)) => {
					Refused(WitnessedAdapterError::Journal(error))
				}
				ContinuationReservationError::Preflight(_)
				| ContinuationReservationError::PriorReplay(_)
				| ContinuationReservationError::Admission(_) => {
					Unconfirmed(WitnessedAdapterError::Journal(error))
				}
				_ => Uncertain(WitnessedAdapterError::Journal(error)),
			})
	}
}

fn transition(kind: FrameKind) -> Option<(WitnessPrepublicationPhase, RemoteWitnessedReplayPhase)> {
	use RemoteWitnessedReplayPhase as Replay;
	use WitnessPrepublicationPhase as Native;
	Some(match kind {
		FrameKind::StageSealed => (Native::Seal, Replay::Sealed),
		FrameKind::VerificationRecorded => (Native::Verify, Replay::Verified),
		FrameKind::MetadataRecorded => (Native::Metadata, Replay::MetadataReady),
		FrameKind::PublishIntent => (Native::Intent, Replay::PublishIntentRequiresObservation),
		_ => return None,
	})
}

pub(in crate::assembly::linux::remote_continued) fn confirm_successor(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
	witness: RemoteWitnessIntent,
	expected: RemoteReplayBoundary,
	phase: RemoteWitnessedReplayPhase,
) -> Result<(), WitnessAdmissionError> {
	let replay = replay_remote_witnessed_closeout(input, trust, selection)
		.map_err(WitnessAdmissionError::Format)?;
	if replay.issue().is_some()
		|| replay.phase() != phase
		|| replay.boundary() != expected
		|| replay.witness() != Some(witness)
	{
		return Err(WitnessAdmissionError::Binding);
	}
	Ok(())
}
