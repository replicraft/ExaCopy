//! Freshly admitted live barriers following an independently accepted positive kind 8.

use std::cell::OnceCell;
use std::io::{Cursor, Read};

use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::remote_download::RemoteBootstrapTrust;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::RemoteWitnessIntent;
use exacopy_journal::remote_download::witness::budget::{
	WitnessedPassBudget, WitnessedPassProgress,
};
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	PreparedWitnessedCloseout, RemoteWitnessedReplayPhase, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};
use exacopy_platform::linux::{
	WitnessDurabilityAppend, WitnessDurabilityError, WitnessDurabilityRequest,
	WitnessPublicationObservation, WitnessReservationAuthority,
};

use super::{SubmittedPublication, WitnessAdmissionError, WitnessPass, model_head};

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum WitnessedDurabilityError {
	Binding,
	#[cfg_attr(
		feature = "experimental-verified-prefix-resume",
		expect(dead_code, reason = "retains the exact private error cause")
	)]
	Native(WitnessDurabilityError<WitnessAdmissionError>),
}

pub(in crate::assembly::linux::remote_continued) struct LiveDurability<'a, 'history> {
	pub(in crate::assembly::linux::remote_continued) trust: &'a RemoteBootstrapTrust<'history>,
	pub(in crate::assembly::linux::remote_continued) selection:
		&'a RemoteWitnessedReplaySelection<'history>,
	pub(in crate::assembly::linux::remote_continued) budget: WitnessedPassBudget,
	pub(in crate::assembly::linux::remote_continued) witnessed: RemoteWitnessIntent,
	pub(in crate::assembly::linux::remote_continued) observed: RemoteReplayBoundary,
	pub(in crate::assembly::linux::remote_continued) target: LinuxFileIdentity,
}

impl LiveDurability<'_, '_> {
	pub(in crate::assembly::linux::remote_continued) fn prepare(
		&self,
		input: impl Read,
	) -> Result<PreparedWitnessedCloseout, WitnessAdmissionError> {
		let replay = replay_remote_witnessed_closeout(input, self.trust, self.selection)
			.map_err(WitnessAdmissionError::Format)?;
		if replay.boundary() != self.observed
			|| replay.issue().is_some()
			|| replay.phase() != RemoteWitnessedReplayPhase::PublishedObserved
			|| replay.observed_outcome() != Some(RemoteWitnessedOutcome::Submitted(self.target))
			|| replay.witness() != Some(self.witnessed)
		{
			return Err(WitnessAdmissionError::Binding);
		}
		self.budget
			.recheck_remaining(self.observed, WitnessedPassProgress::PublishedObserved)
			.map_err(|_| WitnessAdmissionError::Binding)?;
		let proposal = replay
			.prepare_live_durability(self.trust, self.witnessed, self.target)
			.map_err(WitnessAdmissionError::Format)?;
		self.budget
			.recheck_remaining(proposal.successor(), WitnessedPassProgress::Durable)
			.map_err(|_| WitnessAdmissionError::Binding)?;
		Ok(proposal)
	}

	fn confirm(
		&self,
		input: impl Read,
		proposal: &PreparedWitnessedCloseout,
	) -> Result<(), WitnessAdmissionError> {
		let replay = replay_remote_witnessed_closeout(input, self.trust, self.selection)
			.map_err(WitnessAdmissionError::Format)?;
		proposal
			.confirms_live_durability(&replay, self.witnessed, self.target)
			.then_some(())
			.ok_or(WitnessAdmissionError::Binding)
	}
}

impl SubmittedPublication<'_, '_, '_, '_> {
	/// Confirms the required live barriers and exactly one durable kind 9.
	/// Failure preserves the original native observation and accepted kind 8.
	pub(in crate::assembly::linux::remote_continued) fn record_durability(
		&mut self,
		observed: RemoteReplayBoundary,
	) -> Result<RemoteReplayBoundary, WitnessedDurabilityError> {
		use WitnessedDurabilityError as Error;
		let pass = self.pass;
		let witness = self.witness;
		let WitnessPublicationObservation::Published(published) = self.native.observation() else {
			return Err(Error::Binding);
		};
		let published = *published;
		let target =
			LinuxFileIdentity::new(published.identity().device(), published.identity().inode());
		let consent = pass.approval.commitment();
		if witness.consent() != consent
			|| !std::ptr::eq(pass.current.verified(), pass.selection.qualification)
			|| self.native.qualification_facts() != pass.current.facts()
			|| self.native.observation_head() != Some(model_head(observed))
		{
			return Err(Error::Binding);
		}
		let selected = OnceCell::<PreparedWitnessedCloseout>::new();
		let live = LiveDurability {
			trust: pass.trust,
			selection: pass.selection,
			budget: pass.budget,
			witnessed: witness,
			observed,
			target,
		};
		let head = self
			.native
			.record_durability(
				model_head(observed),
				|stamp, input| {
					if stamp != published {
						return Err(WitnessAdmissionError::Binding);
					}
					let codec = live.prepare(input)?;
					let successor = codec.successor();
					let native = WitnessDurabilityAppend {
						previous: model_head(codec.previous()),
						successor: model_head(successor),
						encoded: codec.encoded().to_vec(),
					};
					selected
						.set(codec)
						.map_err(|_| WitnessAdmissionError::Binding)?;
					Ok(native)
				},
				|input, proposed| {
					let codec = selected.get().ok_or(WitnessAdmissionError::Binding)?;
					live.confirm(input.chain(Cursor::new(proposed.encoded.as_slice())), codec)
				},
				|request| {
					let successor = selected
						.get()
						.ok_or(WitnessAdmissionError::Binding)?
						.successor();
					if !matches_gate(pass, observed, successor, request) {
						return Err(WitnessAdmissionError::Binding);
					}
					let mut guard = pass
						.approval
						.enter(pass.grant, pass.names)
						.map_err(WitnessAdmissionError::Consent)?;
					if !guard.recheck_locked() {
						return Err(WitnessAdmissionError::Consent(
							crate::assembly::linux::remote_witness_authority::ConsentRefusal::Clock,
						));
					}
					Ok(guard)
				},
				|input, _| {
					let codec = selected.get().ok_or(WitnessAdmissionError::Binding)?;
					live.confirm(input, codec)
				},
			)
			.map_err(Error::Native)?;
		let codec = selected.into_inner().ok_or(Error::Binding)?;
		if model_head(codec.successor()) != head {
			return Err(Error::Binding);
		}
		Ok(codec.successor())
	}
}

fn matches_gate(
	pass: WitnessPass<'_, '_>,
	observed: RemoteReplayBoundary,
	successor: RemoteReplayBoundary,
	request: WitnessDurabilityRequest<'_>,
) -> bool {
	let consent = pass.approval.commitment();
	let authority = WitnessReservationAuthority {
		qualification: *pass.current.verified().digest().as_bytes(),
		base_grant: consent.base_grant_digest,
		retention_approval: consent.approval_digest,
	};
	let root = pass.current.facts().ids().root;
	request.observation == model_head(observed)
		&& request.successor == model_head(successor)
		&& request.stage == pass.names.retained
		&& request.job.device() == pass.names.job.device()
		&& request.job.inode() == pass.names.job.inode()
		&& request.destination.device() == root.device
		&& request.destination.inode() == root.inode
		&& request.authority == authority
}
