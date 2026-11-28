use std::error::Error;
use std::fmt;
use std::io;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_apply::{ApplyStep, NativeRenameFacts, PublishedFacts};
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{
	ApplyQualificationDigest, ApprovedPublicPlanDigest, LinuxFileIdentity, OwnerDigest,
	OwnerProfileId, OwnerTimestamp, PublicPlanEntryId, RootCapabilityId,
};
use exacopy_model::CopyBinding;
use exacopy_transfer::linux::PublicApplyStageRequest;

use super::super::CopyRoots;
use super::qualification::LocalApplyQualificationEnrollment;

mod clock;
mod effects;
#[cfg(kani)]
pub(crate) use effects::phase_proof;
mod scope;
#[cfg(test)]
mod tests;

use clock::{ClockSample, GrantClock, QualificationWindow};
use effects::{ExpectedSettlement, GrantState, journal_identity};
use scope::AttemptScope;

/// A root role from independent local policy, with its one allowed component.
#[derive(Clone, Copy, Debug)]
pub struct LocalApplyRootSelection<'policy> {
	/// The authorization alias assigned to this root role.
	pub alias: RootCapabilityId,
	/// The independently selected device and inode of the held directory.
	pub identity: LinuxFileIdentity,
	/// Exact raw source or destination component within this role.
	pub name: UnixComponent<'policy>,
}

/// Independent policy for one trusted local foreground confirmation.
///
/// The embedding host supplies these values from its own policy selection.
/// Candidate Plan, owner, journal and qualification bytes cannot configure it.
pub struct LocalApplyHostSelection<'policy> {
	/// Approved canonical public Plan digest.
	pub approved_plan: ApprovedPublicPlanDigest,
	/// The exact approved entry.
	pub public_entry: PublicPlanEntryId,
	/// Independently selected source role.
	pub source: LocalApplyRootSelection<'policy>,
	/// Independently selected destination role.
	pub destination: LocalApplyRootSelection<'policy>,
	/// Independently selected owner profile.
	pub owner_profile: OwnerProfileId,
	/// Independently configured owner verification key.
	pub owner_key: &'policy VerifyingKey,
	/// Separately configured process-crash qualification enrollment.
	pub enrollment: &'policy LocalApplyQualificationEnrollment<'policy>,
	/// Finite, nonzero lifetime measured from issuance.
	pub duration: Duration,
}

/// One trusted host selection, consumed when issuing a grant.
///
/// Provision a new selection and obtain fresh independent confirmation for a
/// separate invocation. The host controls the call site and the provenance of
/// that selection and confirmation.
pub struct LocalApplyIssuer<'policy> {
	host: LocalApplyHostSelection<'policy>,
}

impl<'policy> LocalApplyIssuer<'policy> {
	/// Accepts one selection from the embedding application's trusted policy.
	/// # Errors
	/// Refuses missing identifiers, invalid key roles, or an invalid lifetime.
	pub fn from_host_selection(
		host: LocalApplyHostSelection<'policy>,
	) -> Result<Self, LocalApplyGrantError> {
		if host.approved_plan.as_bytes() == &[0; 32]
			|| host.public_entry.as_bytes() == &[0; 16]
			|| host.source.identity.inode() == 0
			|| host.destination.identity.inode() == 0
			|| host.duration.is_zero()
			|| host.enrollment.attestor_id == [0; 16]
			|| host.enrollment.record_digest.as_bytes() == &[0; 32]
			|| host.owner_key == host.enrollment.attestor_key
			|| !canonical_key(host.owner_key)
			|| !canonical_key(host.enrollment.attestor_key)
		{
			return Err(LocalApplyGrantError::Selection);
		}
		Ok(Self { host })
	}

	/// Consumes this issuer even when the independently confirmed action differs.
	/// # Errors
	/// Refuses a different action, held root, signer, or unusable time window.
	pub fn issue<'root>(
		self,
		confirmed: ApprovedPublicPlanDigest,
		roots: CopyRoots<'root>,
		request: &PublicApplyStageRequest<'_, '_, '_>,
	) -> Result<LocalApplyGrant<'policy, 'root>, LocalApplyGrantError> {
		let initial = ClockSample::now()?;
		let scope = AttemptScope::capture(&self.host, confirmed, roots, request)?;
		let expiry = scope
			.binding
			.expires_at
			.ok_or(LocalApplyGrantError::Scope)?;
		let clock = GrantClock::new(initial, self.host.duration, scope.created, expiry)?;
		Ok(LocalApplyGrant {
			roots,
			scope,
			target: self.host.destination,
			enrollment: self.host.enrollment,
			state: Mutex::new(GrantState::new(clock)),
		})
	}
}

fn canonical_key(key: &VerifyingKey) -> bool {
	!key.is_weak() && key.to_edwards().compress().as_bytes() == key.as_bytes()
}

/// Revocable, one-use foreground grant bound to one original held local action.
///
/// Reusing the same grant does not authorize a second attempt. Its per-effect
/// guards and the publication transition are private to the composed SDK path.
pub struct LocalApplyGrant<'policy, 'root> {
	roots: CopyRoots<'root>,
	scope: AttemptScope,
	target: LocalApplyRootSelection<'policy>,
	enrollment: &'policy LocalApplyQualificationEnrollment<'policy>,
	state: Mutex<GrantState>,
}

impl LocalApplyGrant<'_, '_> {
	/// Revokes all mutations that have yet to enter this grant.
	///
	/// Waits for an already-admitted bounded native effect. Settlement of an
	/// already-submitted rename can continue after this call.
	pub fn revoke(&self) {
		if let Ok(mut state) = self.lock() {
			state.retire(LocalApplyGrantError::Revoked);
		}
	}

	pub(super) fn enrollment(&self) -> &LocalApplyQualificationEnrollment<'_> {
		self.enrollment
	}

	pub(super) fn claim(
		&self,
		roots: CopyRoots<'_>,
		request: &PublicApplyStageRequest<'_, '_, '_>,
	) -> Result<(), LocalApplyGrantError> {
		// Compute the bounded canonical comparisons outside the revocation lock.
		let matches = self.scope.matches(self.roots, roots, request);
		let mut state = self.lock()?;
		state.claim(matches, ClockSample::now()).map(|_| ())
	}

	pub(super) fn qualify(
		&self,
		record: ApplyQualificationDigest,
		starts_at: OwnerTimestamp,
		expires_at: OwnerTimestamp,
	) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		let mut state = self.lock()?;
		state.qualify(
			record == self.enrollment.record_digest,
			ClockSample::now(),
			QualificationWindow {
				starts_at,
				expires_at,
			},
		)
	}

	pub(super) fn recheck_clock(&self) -> Result<OwnerTimestamp, LocalApplyGrantError> {
		let mut state = self.lock()?;
		state.observe(ClockSample::now())
	}

	pub(super) fn enter(&self, step: ApplyStep) -> io::Result<LocalApplyEffectGuard<'_>> {
		let mut state = self.lock().map_err(admission_error)?;
		state
			.enter(
				step,
				self.scope.binding.stream_length.get(),
				self.scope.max_buffer,
				ClockSample::now(),
			)
			.map_err(admission_error)?;
		Ok(LocalApplyEffectGuard { _state: state })
	}

	pub(super) fn bind_owner(&self, owner: OwnerDigest) -> Result<(), LocalApplyGrantError> {
		let mut state = self.lock()?;
		state.bind_owner(owner, ClockSample::now())
	}

	pub(super) fn bind_stage(
		&self,
		binding: CopyBinding,
		stage: LinuxFileIdentity,
	) -> Result<(), LocalApplyGrantError> {
		let matches = binding == self.scope.copy
			&& stage.inode() != 0
			&& stage.device() == self.target.identity.device()
			&& stage != self.scope.source_file
			&& stage != self.target.identity;
		let mut state = self.lock()?;
		state.bind_stage(matches, stage, ClockSample::now())
	}

	pub(super) fn bind_intent(
		&self,
		owner: OwnerDigest,
		binding: CopyBinding,
		head: ChainHead,
	) -> Result<(), LocalApplyGrantError> {
		let mut state = self.lock()?;
		state.bind_intent(binding == self.scope.copy, owner, head, ClockSample::now())
	}

	pub(super) fn enter_rename(
		&self,
		owner: OwnerDigest,
		binding: CopyBinding,
		head: ChainHead,
		facts: NativeRenameFacts<'_>,
	) -> io::Result<LocalApplyEffectGuard<'_>> {
		let matches = binding == self.scope.copy
			&& facts.binding == binding
			&& facts.target.as_bytes() == self.target.name.as_bytes()
			&& journal_identity(facts.destination) == self.target.identity
			&& facts.stage_directory.device == facts.destination.device
			&& facts.stage_directory.inode != 0
			&& facts.stage_directory != facts.destination
			&& facts.stage_directory != facts.stage;
		let expected = ExpectedSettlement {
			target: facts.stage,
			stage_directory: facts.stage_directory,
			destination: facts.destination,
		};
		let mut state = self.lock().map_err(admission_error)?;
		state
			.enter_rename(matches, owner, head, expected, ClockSample::now())
			.map_err(admission_error)?;
		Ok(LocalApplyEffectGuard { _state: state })
	}

	pub(super) fn bind_settled(&self, facts: PublishedFacts) -> Result<(), LocalApplyGrantError> {
		self.lock()?.bind_settled(facts)
	}

	fn lock(&self) -> Result<MutexGuard<'_, GrantState>, LocalApplyGrantError> {
		lock_state(&self.state)
	}
}

fn lock_state(
	state: &Mutex<GrantState>,
) -> Result<MutexGuard<'_, GrantState>, LocalApplyGrantError> {
	state.lock().map_err(|_| LocalApplyGrantError::Poisoned)
}

pub(super) struct LocalApplyEffectGuard<'gate> {
	_state: MutexGuard<'gate, GrantState>,
}

fn admission_error(cause: LocalApplyGrantError) -> io::Error {
	io::Error::new(io::ErrorKind::PermissionDenied, cause)
}

/// The exact local grant could not authorize an invocation or effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LocalApplyGrantError {
	/// Independent host policy was invalid.
	Selection,
	/// Current action or observation differs from the selected scope.
	Scope,
	/// The grant already claimed its invocation or spent its publication admission.
	Spent,
	/// The requested step is not admitted in the current phase.
	Phase,
	/// The authority window is not current.
	Expired,
	/// A clock sample could not be trusted.
	Clock,
	/// Revocation forbids a new effect.
	Revoked,
	/// The grant lock was poisoned and cannot authorize a new effect.
	Poisoned,
}

impl fmt::Display for LocalApplyGrantError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Selection => "invalid independent local apply selection",
			Self::Scope => "local apply scope differs from its foreground confirmation",
			Self::Spent => "local apply authorization was already used",
			Self::Phase => "local apply operation is out of phase",
			Self::Expired => "local apply authority window is not current",
			Self::Clock => "local apply clock is unavailable or moved backward",
			Self::Revoked => "local apply authority was revoked",
			Self::Poisoned => "local apply authority state is poisoned",
		})
	}
}

impl Error for LocalApplyGrantError {}
