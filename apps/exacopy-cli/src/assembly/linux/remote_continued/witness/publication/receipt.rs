//! Live selector-2 receipt composition under the originally held publication.

use std::cell::OnceCell;
use std::io::{Cursor, Read};

use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::remote_download::RemoteBootstrapTrust;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::witness::budget::{
	WitnessedPassBudget, WitnessedPassProgress as Progress,
};
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use exacopy_journal::remote_download::witness::replay::{
	PreparedWitnessedCloseout, RemoteWitnessedCloseoutReplay, RemoteWitnessedReplaySelection,
	replay_remote_witnessed_closeout,
};
use exacopy_journal::remote_download::witness::{RemoteReceiptReady, RemoteWitnessIntent};
use exacopy_platform::linux::{
	FileIdentity, WitnessPublicationObservation, WitnessReceiptAppend, WitnessReceiptEffect,
	WitnessReceiptError, WitnessReceiptIdentity, WitnessReceiptNames, WitnessReceiptPlacement,
	WitnessReceiptPlan, WitnessReceiptRequest, WitnessReservationAuthority,
};

use crate::assembly::linux::remote_witness_authority::{ConsentRefusal, WitnessMutationGuard};

use super::{SubmittedPublication, WitnessAdmissionError as Error, WitnessPass, model_head};

pub(in crate::assembly::linux::remote_continued) struct LiveReceipt<'a, 'history> {
	pub(in crate::assembly::linux::remote_continued) trust: &'a RemoteBootstrapTrust<'history>,
	pub(in crate::assembly::linux::remote_continued) selection:
		&'a RemoteWitnessedReplaySelection<'history>,
	pub(in crate::assembly::linux::remote_continued) budget: WitnessedPassBudget,
	pub(in crate::assembly::linux::remote_continued) witness: RemoteWitnessIntent,
	pub(in crate::assembly::linux::remote_continued) durable: RemoteReplayBoundary,
	pub(in crate::assembly::linux::remote_continued) target: LinuxFileIdentity,
}

pub(in crate::assembly::linux::remote_continued) struct PendingPlan {
	pub(in crate::assembly::linux::remote_continued) proposal: PreparedWitnessedCloseout,
	pub(in crate::assembly::linux::remote_continued) bytes: Vec<u8>,
	pub(in crate::assembly::linux::remote_continued) pending: [u8; 101],
	pub(in crate::assembly::linux::remote_continued) final_name: [u8; 99],
	receipt: LinuxFileIdentity,
	target_parent: LinuxFileIdentity,
	digest: [u8; 32],
}

impl LiveReceipt<'_, '_> {
	pub(in crate::assembly::linux::remote_continued) fn prepare_pending(
		&self,
		input: impl Read,
		receipt: LinuxFileIdentity,
	) -> Result<PendingPlan, Error> {
		let replay = self.live_replay(input)?;
		let basis = replay.durable_receipt_basis().map_err(Error::Format)?;
		let remaining = self
			.budget
			.recheck_remaining(self.durable, Progress::Durable)
			.map_err(|_| Error::Binding)?;
		if basis.boundary() != self.durable || basis.length() > remaining.receipt_bytes() {
			return Err(Error::Binding);
		}
		let proposal = replay
			.prepare_live_receipt_ready(self.trust, self.witness, receipt)
			.map_err(Error::Format)?;
		self.budget
			.recheck_remaining(proposal.successor(), Progress::ReceiptReady)
			.map_err(|_| Error::Binding)?;
		Ok(PendingPlan {
			proposal,
			receipt,
			target_parent: basis.target_parent(),
			digest: basis.digest(),
			bytes: basis.bytes().to_vec(),
			pending: basis
				.pending_name()
				.try_into()
				.map_err(|_| Error::Binding)?,
			final_name: basis.final_name().try_into().map_err(|_| Error::Binding)?,
		})
	}

	pub(in crate::assembly::linux::remote_continued) fn confirm_pending(
		&self,
		input: impl Read,
		pending: &PendingPlan,
	) -> Result<RemoteReceiptReady, Error> {
		let replay = self.live_replay(input)?;
		self.inspect_ready(&replay, pending)
	}

	fn inspect_ready(
		&self,
		replay: &RemoteWitnessedCloseoutReplay,
		pending: &PendingPlan,
	) -> Result<RemoteReceiptReady, Error> {
		let inspection = replay.receipt_ready_inspection().map_err(Error::Format)?;
		let ready = inspection.record();
		if !pending
			.proposal
			.confirms_live_receipt_ready(replay, self.witness, pending.receipt)
			|| inspection.durability_boundary() != self.durable
			|| inspection.target_parent() != pending.target_parent
			|| inspection.bytes() != pending.bytes
			|| inspection.pending_name() != pending.pending
			|| inspection.final_name() != pending.final_name
			|| ready.digest() != pending.digest
			|| usize::from(ready.length()) != pending.bytes.len()
		{
			return Err(Error::Binding);
		}
		self.budget
			.recheck_remaining(ready.boundary(), Progress::ReceiptReady)
			.map_err(|_| Error::Binding)?;
		Ok(ready)
	}

	pub(in crate::assembly::linux::remote_continued) fn prepare_commit(
		&self,
		input: impl Read,
		pending: &PendingPlan,
		ready: RemoteReceiptReady,
	) -> Result<PreparedWitnessedCloseout, Error> {
		let replay = self.live_replay(input)?;
		if self.inspect_ready(&replay, pending)? != ready {
			return Err(Error::Binding);
		}
		let proposal = replay
			.prepare_live_receipt_commit(self.trust, self.witness, ready)
			.map_err(Error::Format)?;
		self.budget
			.recheck_remaining(proposal.successor(), Progress::ReceiptCommitted)
			.map_err(|_| Error::Binding)?;
		Ok(proposal)
	}

	pub(in crate::assembly::linux::remote_continued) fn confirm_commit(
		&self,
		input: impl Read,
		proposal: &PreparedWitnessedCloseout,
		ready: RemoteReceiptReady,
	) -> Result<(), Error> {
		let replay = self.live_replay(input)?;
		if !proposal.confirms_live_receipt_commit(&replay, self.witness, ready) {
			return Err(Error::Binding);
		}
		self.budget
			.recheck_remaining(replay.boundary(), Progress::ReceiptCommitted)
			.map_err(|_| Error::Binding)?;
		Ok(())
	}

	fn live_replay(&self, input: impl Read) -> Result<RemoteWitnessedCloseoutReplay, Error> {
		let replay = replay_remote_witnessed_closeout(input, self.trust, self.selection)
			.map_err(Error::Format)?;
		if replay.issue().is_some()
			|| replay.witness() != Some(self.witness)
			|| replay.observed_outcome() != Some(RemoteWitnessedOutcome::Submitted(self.target))
		{
			return Err(Error::Binding);
		}
		Ok(replay)
	}
}

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) enum WitnessedReceiptError {
	Binding,
	Pending {
		placement: WitnessReceiptPlacement,
		cause: WitnessReceiptError<Error>,
	},
	Commit {
		ready: RemoteReplayBoundary,
		placement: WitnessReceiptPlacement,
		cause: WitnessReceiptError<Error>,
	},
}

#[derive(Debug)]
pub(in crate::assembly::linux::remote_continued) struct WitnessedReceiptCompletion {
	#[cfg(test)]
	pub(in crate::assembly::linux::remote_continued) ready: RemoteReplayBoundary,
	#[cfg(feature = "experimental-verified-prefix-resume")]
	pub(in crate::assembly::linux::remote_continued) digest: [u8; 32],
	pub(in crate::assembly::linux::remote_continued) committed: RemoteReplayBoundary,
	pub(in crate::assembly::linux::remote_continued) bytes: Vec<u8>,
}

impl SubmittedPublication<'_, '_, '_, '_> {
	/// Uses the original live reservation to complete one selector-2 receipt.
	/// Errors retain the native public observation and known journal milestones.
	pub(in crate::assembly::linux::remote_continued) fn record_receipt(
		&mut self,
		durable: RemoteReplayBoundary,
	) -> Result<WitnessedReceiptCompletion, WitnessedReceiptError> {
		use WitnessedReceiptError as Failure;
		let pass = self.pass;
		let witness = self.witness;
		let WitnessPublicationObservation::Published(stamp) = self.native.observation() else {
			return Err(Failure::Binding);
		};
		let target = LinuxFileIdentity::new(stamp.identity().device(), stamp.identity().inode());
		if witness.binding().stage() != target
			|| witness.consent() != pass.approval.commitment()
			|| !std::ptr::eq(pass.current.verified(), pass.selection.qualification)
			|| self.native.qualification_facts() != pass.current.facts()
			|| self.native.durability_head() != Some(model_head(durable))
		{
			return Err(Failure::Binding);
		}
		let live = LiveReceipt {
			trust: pass.trust,
			selection: pass.selection,
			budget: pass.budget,
			witness,
			durable,
			target,
		};
		let pending = OnceCell::<PendingPlan>::new();
		let accepted = OnceCell::<RemoteReceiptReady>::new();
		let ready_head = self
			.native
			.record_receipt_ready(
				model_head(durable),
				|identity, input| {
					if !matches_identity(pass, witness, identity) {
						return Err(Error::Binding);
					}
					let plan = live.prepare_pending(input, journal_identity(identity.receipt))?;
					if journal_identity(identity.destination) != plan.target_parent {
						return Err(Error::Binding);
					}
					let native = WitnessReceiptPlan {
						names: WitnessReceiptNames {
							pending: plan.pending,
							final_name: plan.final_name,
						},
						bytes: plan.bytes.clone(),
						append: native_append(&plan.proposal),
					};
					pending.set(plan).map_err(|_| Error::Binding)?;
					Ok(native)
				},
				|input, append| {
					live.confirm_pending(
						input.chain(Cursor::new(append.encoded.as_slice())),
						selected(&pending)?,
					)?;
					Ok(())
				},
				|request| {
					let pending = selected(&pending)?;
					admit(pass, witness, pending, &pending.proposal, request)
				},
				|input, _| {
					let ready = live.confirm_pending(input, selected(&pending)?)?;
					accepted.set(ready).map_err(|_| Error::Binding)
				},
			)
			.map_err(|cause| Failure::Pending {
				placement: self.native.receipt_placement(),
				cause,
			})?;
		let pending = pending.into_inner().ok_or(Failure::Binding)?;
		let ready = accepted.into_inner().ok_or(Failure::Binding)?;
		if ready_head != model_head(ready.boundary())
			|| self.native.receipt_ready_head() != Some(ready_head)
		{
			return Err(Failure::Binding);
		}
		let commit = OnceCell::<PreparedWitnessedCloseout>::new();
		let committed_head = self
			.native
			.commit_receipt(
				ready_head,
				|input| {
					let proposal = live.prepare_commit(input, &pending, ready)?;
					let native = native_append(&proposal);
					commit.set(proposal).map_err(|_| Error::Binding)?;
					Ok(native)
				},
				|input, append| {
					live.confirm_commit(
						input.chain(Cursor::new(append.encoded.as_slice())),
						selected(&commit)?,
						ready,
					)
				},
				|request| admit(pass, witness, &pending, selected(&commit)?, request),
				|input, _| live.confirm_commit(input, selected(&commit)?, ready),
			)
			.map_err(|cause| Failure::Commit {
				ready: ready.boundary(),
				placement: self.native.receipt_placement(),
				cause,
			})?;
		let committed = commit.into_inner().ok_or(Failure::Binding)?.successor();
		if committed_head != model_head(committed)
			|| self.native.receipt_committed_head() != Some(committed_head)
		{
			return Err(Failure::Binding);
		}
		Ok(WitnessedReceiptCompletion {
			#[cfg(test)]
			ready: ready.boundary(),
			#[cfg(feature = "experimental-verified-prefix-resume")]
			digest: ready.digest(),
			committed,
			bytes: pending.bytes,
		})
	}
}

fn selected<T>(cell: &OnceCell<T>) -> Result<&T, Error> {
	cell.get().ok_or(Error::Binding)
}

fn native_append(proposal: &PreparedWitnessedCloseout) -> WitnessReceiptAppend {
	WitnessReceiptAppend {
		previous: model_head(proposal.previous()),
		successor: model_head(proposal.successor()),
		encoded: proposal.encoded().to_vec(),
	}
}

fn journal_identity(identity: FileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device(), identity.inode())
}

fn matches_identity(
	pass: WitnessPass<'_, '_>,
	witness: RemoteWitnessIntent,
	identity: WitnessReceiptIdentity,
) -> bool {
	let root = pass.current.facts().ids().root;
	let job = journal_identity(identity.job);
	job == pass.names.job
		&& job == witness.job_directory()
		&& journal_identity(identity.destination) == LinuxFileIdentity::new(root.device, root.inode)
}

fn admit<'scope>(
	pass: WitnessPass<'scope, '_>,
	witness: RemoteWitnessIntent,
	pending: &PendingPlan,
	proposal: &PreparedWitnessedCloseout,
	request: WitnessReceiptRequest<'_>,
) -> Result<WitnessMutationGuard<'scope>, Error> {
	let consent = pass.approval.commitment();
	let expected = WitnessReservationAuthority {
		qualification: *pass.current.verified().digest().as_bytes(),
		base_grant: consent.base_grant_digest,
		retention_approval: consent.approval_digest,
	};
	let kind = match request.effect {
		WitnessReceiptEffect::Write
		| WitnessReceiptEffect::AnonymousFileBarrier
		| WitnessReceiptEffect::LinkPending
		| WitnessReceiptEffect::PendingFileBarrier
		| WitnessReceiptEffect::PendingJobBarrier
		| WitnessReceiptEffect::AppendReady => FrameKind::RemoteReceiptReady,
		WitnessReceiptEffect::Promote
		| WitnessReceiptEffect::FinalFileBarrier
		| WitnessReceiptEffect::FinalJobBarrier
		| WitnessReceiptEffect::AppendCommitted => FrameKind::ReceiptCommitted,
	};
	if proposal.kind() != kind
		|| request.authority != expected
		|| request.stage != pass.names.retained
		|| !matches_identity(pass, witness, request.identity)
		|| journal_identity(request.identity.receipt) != pending.receipt
		|| journal_identity(request.identity.destination) != pending.target_parent
		|| request.names.pending != pending.pending
		|| request.names.final_name != pending.final_name
		|| request.previous != model_head(proposal.previous())
		|| request.successor != model_head(proposal.successor())
	{
		return Err(Error::Binding);
	}
	let mut guard = pass
		.approval
		.enter(pass.grant, pass.names)
		.map_err(Error::Consent)?;
	if !guard.recheck_locked() {
		return Err(Error::Consent(ConsentRefusal::Clock));
	}
	Ok(guard)
}
