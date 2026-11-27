//! Current authority for app-private restart of an exact witnessed kind-7 cut.

use std::fmt;
use std::num::NonZeroU64;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::linux_remote_qualification::RemoteDestinationFacts;
use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::remote_download::qualification::continuation::{
	CurrentRemoteWitnessQualification, RemoteContinuationQualificationError,
	VerifiedRemoteWitnessQualification,
};
use exacopy_journal::remote_download::replay::{
	MAX_REMOTE_REPLAY_SEGMENT_BYTES, RemoteReplayBoundary,
};
use exacopy_journal::remote_download::witness::WitnessRetentionCommitment;
use exacopy_journal::remote_download::witness::replay::{
	RemoteWitnessedPublicExpectation, RemoteWitnessedReplaySelection,
};
use exacopy_journal::remote_download::{
	RemoteDownloadContext, RemoteDownloadError, RemoteDownloadOwnerRecord, RemoteDownloadRoute,
	RemoteDownloadScope, RemoteScopeDigest,
};
use exacopy_platform::linux::{
	DestinationRoot, RemoteDestinationEligibilityError, observe_remote_destination,
};

use crate::assembly::linux::remote_download::{RemoteGrant, measure_running_executable};
use crate::assembly::linux::remote_journal::{CurrentGrant, Error, record_identity};

#[cfg(test)]
mod tests;

/// Why current authority for the requested recovery observation was refused.
#[derive(Debug)]
pub enum AuthorityError {
	/// The independent authority inputs disagreed with each other or with the exact cut.
	Binding,
	/// The base grant was refused by the foreground authority.
	Grant(Error),
	/// The explicit approval was withdrawn or consumed.
	ApprovalInactive,
	/// The original deadline expired or the clock became untrustworthy.
	Clock,
	/// The signed scope or retention commitment could not be measured.
	Format(RemoteDownloadError),
	/// The running executable could not be measured.
	Build(std::io::Error),
	/// Native facts could not be obtained for the held destination.
	Destination(RemoteDestinationEligibilityError),
	/// The running build or native facts disagree with the selected operation-2 qualification.
	Qualification(RemoteContinuationQualificationError),
}

impl fmt::Display for AuthorityError {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Binding => out.write_str("witnessed recovery authority binding disagrees"),
			Self::Grant(cause) => write!(out, "witnessed recovery grant refused ({cause})"),
			Self::ApprovalInactive => out.write_str("witnessed recovery approval is inactive"),
			Self::Clock => out.write_str("witnessed recovery approval deadline is unconfirmed"),
			Self::Format(cause) => cause.fmt(out),
			Self::Build(cause) => write!(out, "running executable measurement failed ({cause})"),
			Self::Destination(cause) => cause.fmt(out),
			Self::Qualification(cause) => cause.fmt(out),
		}
	}
}

impl std::error::Error for AuthorityError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Binding | Self::ApprovalInactive | Self::Clock => None,
			Self::Grant(cause) => Some(cause),
			Self::Format(cause) => Some(cause),
			Self::Build(cause) => Some(cause),
			Self::Destination(cause) => Some(cause),
			Self::Qualification(cause) => Some(cause),
		}
	}
}

/// Explicit foreground approval to record one recovered observation and retain the witness.
///
/// The caller independently selects the original owner, exact kind-7 cut, signed scope and
/// original retention commitment through its protected authorization context. The application
/// must obtain affirmative current approval before calling [`Self::select`]. The protected
/// witness stays linked to the public file. The original signed POSIX deadline still applies.
pub struct RecoveryApproval<'grant> {
	grant: &'grant RemoteGrant,
	intent: RemoteReplayBoundary,
	context: RemoteDownloadContext,
	scope: RemoteScopeDigest,
	commitment: WitnessRetentionCommitment,
	deadline: ApprovalDeadline,
	state: Mutex<ApprovalState>,
}

enum ApprovalState {
	Armed,
	Withdrawn,
	Consumed,
}

impl<'grant> RecoveryApproval<'grant> {
	/// Expresses explicit approval for an independently selected original kind-7 EOF.
	///
	/// Authenticate the invoker's explicit selection and retain the still-current original
	/// scoped grant from the independent protected issuer. The historical digest gives
	/// no authority to mint a replacement lease. A trustworthy wall clock across the
	/// restart is an independent premise.
	///
	/// # Errors
	/// Refuses an invalid boundary, a foreign commitment, an expired deadline or an unusable clock.
	pub fn select(
		intent: RemoteReplayBoundary,
		context: RemoteDownloadContext,
		scope: RemoteScopeDigest,
		commitment: WitnessRetentionCommitment,
		grant: &'grant RemoteGrant,
	) -> Result<Self, AuthorityError> {
		if intent.head.sequence() == 0
			|| intent.offset == 0
			|| intent.offset > MAX_REMOTE_REPLAY_SEGMENT_BYTES
			|| WitnessRetentionCommitment::measure(
				context,
				scope,
				commitment.base_grant_digest,
				commitment.deadline,
			)
			.map_err(AuthorityError::Format)?
				!= commitment
		{
			return Err(AuthorityError::Binding);
		}
		if grant.recheck(scope).map_err(AuthorityError::Grant)? != commitment.base_grant_digest {
			return Err(AuthorityError::Binding);
		}
		let deadline = ApprovalDeadline::at(ClockSample::now()?, commitment.deadline)?;
		Ok(Self {
			grant,
			intent,
			context,
			scope,
			commitment,
			deadline,
			state: Mutex::new(ApprovalState::Armed),
		})
	}

	/// Returns the exact independently selected original kind-7 cut.
	#[must_use]
	pub const fn intent(&self) -> RemoteReplayBoundary {
		self.intent
	}

	/// Withdraws the approval, serialized with any already-admitted synchronous append.
	pub fn withdraw(&self) {
		*self.state.lock().unwrap_or_else(PoisonError::into_inner) = ApprovalState::Withdrawn;
	}

	/// Binds the already authenticated owner and independent inputs to the actual destination.
	pub(super) fn bind<'held>(
		&'held self,
		root: &'held DestinationRoot,
		owner: &RemoteDownloadOwnerRecord,
		owner_key: &VerifyingKey,
		scope: &'held RemoteDownloadScope,
		selection: &RemoteWitnessedReplaySelection<'held>,
	) -> Result<CurrentRecoveryAuthority<'held>, AuthorityError> {
		let manifest = owner.manifest();
		let context = RemoteDownloadContext {
			owner: owner.digest(),
			job: manifest.job,
			entry: manifest.scope.entry,
		};
		let route = match scope.source.route() {
			RemoteDownloadRoute::ResolvedDirect { .. } => {
				RemoteQualificationRouteClass::DirectPinnedTcpV1
			}
			RemoteDownloadRoute::EmbeddedWireGuard { .. } => {
				RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1
			}
			_ => return Err(AuthorityError::Binding),
		};
		let qualification = selection.qualification;
		if context != self.context
			|| &manifest.scope != scope
			|| scope.digest().map_err(AuthorityError::Format)? != self.scope
			|| scope.metadata_policy != SftpDataOnlyV1::digest()
			|| scope.destination.parent() != record_identity(root.identity())
			|| selection.grant_digest != self.commitment.base_grant_digest
			|| qualification.scope().common.route != route
			|| !qualification.matches_owner(owner_key)
		{
			return Err(AuthorityError::Binding);
		}
		let grant_digest = self
			.grant
			.recheck(self.scope)
			.map_err(AuthorityError::Grant)?;
		if grant_digest != self.commitment.base_grant_digest {
			return Err(AuthorityError::Binding);
		}
		let build = measure_running_executable().map_err(AuthorityError::Build)?;
		let facts = observe_remote_destination(root).map_err(AuthorityError::Destination)?;
		qualification
			.match_current(build, &facts)
			.map_err(AuthorityError::Qualification)?;
		Ok(CurrentRecoveryAuthority {
			approval: self,
			root,
			scope,
			job_directory: manifest.job_directory,
			qualification,
			build,
			facts,
		})
	}

	fn matches_cut(
		&self,
		intent: RemoteReplayBoundary,
		context: RemoteDownloadContext,
		scope: RemoteScopeDigest,
		commitment: WitnessRetentionCommitment,
	) -> bool {
		intent == self.intent
			&& context == self.context
			&& scope == self.scope
			&& commitment == self.commitment
	}

	fn enter_once(
		&self,
		revalidate_qualification: impl FnOnce() -> Result<(), AuthorityError>,
	) -> Result<RecoveryEffectGuard<'_>, AuthorityError> {
		let grant = self
			.grant
			.enter_effect(self.scope, self.commitment.base_grant_digest)
			.map_err(AuthorityError::Grant)?;
		let mut approval = self
			.state
			.lock()
			.map_err(|_| AuthorityError::ApprovalInactive)?;
		if !matches!(*approval, ApprovalState::Armed) {
			return Err(AuthorityError::ApprovalInactive);
		}
		*approval = ApprovalState::Consumed;
		let mut guard = RecoveryEffectGuard {
			_approval: approval,
			_grant: grant,
			original_grant: self.grant,
			deadline: &self.deadline,
			last: self.deadline.anchor,
		};
		guard.confirm()?;
		revalidate_qualification()?;
		Ok(guard)
	}
}

/// Authority observed for this held root and one exact historical witnessed attempt.
pub(super) struct CurrentRecoveryAuthority<'held> {
	approval: &'held RecoveryApproval<'held>,
	root: &'held DestinationRoot,
	scope: &'held RemoteDownloadScope,
	job_directory: LinuxFileIdentity,
	qualification: &'held VerifiedRemoteWitnessQualification,
	build: [u8; 32],
	facts: RemoteDestinationFacts,
}

impl CurrentRecoveryAuthority<'_> {
	pub(super) fn current(&self) -> Result<CurrentRemoteWitnessQualification<'_>, AuthorityError> {
		self.qualification
			.match_current(self.build, &self.facts)
			.map_err(AuthorityError::Qualification)
	}

	/// Enters current authority immediately before the one scoped journal append.
	pub(super) fn enter(
		&self,
		expected: &RemoteWitnessedPublicExpectation<'_>,
	) -> Result<RecoveryEffectGuard<'_>, AuthorityError> {
		let witness = expected.witness();
		let binding = witness.binding();
		if !self.approval.matches_cut(
			expected.boundary(),
			binding.context(),
			binding.scope(),
			witness.consent(),
		) || witness.job_directory() != self.job_directory
			|| expected.destination() != &self.scope.destination
			|| expected.extent().get() > self.scope.maximum_extent.get()
		{
			return Err(AuthorityError::Binding);
		}
		self.approval.enter_once(|| {
			let build = measure_running_executable().map_err(AuthorityError::Build)?;
			let facts =
				observe_remote_destination(self.root).map_err(AuthorityError::Destination)?;
			self.qualification
				.match_current(build, &facts)
				.map_err(AuthorityError::Qualification)?;
			Ok(())
		})
	}
}

#[must_use]
pub(super) struct RecoveryEffectGuard<'approval> {
	// Drop the narrower approval lock before the grant lock.
	_approval: MutexGuard<'approval, ApprovalState>,
	_grant: MutexGuard<'approval, bool>,
	original_grant: &'approval RemoteGrant,
	deadline: &'approval ApprovalDeadline,
	last: ClockSample,
}

impl RecoveryEffectGuard<'_> {
	/// Rechecks both deadlines after final custody probes and before the journal write.
	pub(super) fn confirm(&mut self) -> Result<(), AuthorityError> {
		self.confirm_at(ClockSample::now()?)
	}

	fn confirm_at(&mut self, clock: ClockSample) -> Result<(), AuthorityError> {
		self.deadline.check(clock, self.last)?;
		self.original_grant
			.remaining_from(clock.after)
			.map_err(|cause| AuthorityError::Grant(Error::Grant(cause)))?;
		self.last = clock;
		Ok(())
	}
}

#[derive(Clone, Copy)]
struct ClockSample {
	before: Instant,
	wall: Duration,
	after: Instant,
}

impl ClockSample {
	fn now() -> Result<Self, AuthorityError> {
		let before = Instant::now();
		let wall = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_err(|_| AuthorityError::Clock)?;
		let after = Instant::now();
		Ok(Self {
			before,
			wall,
			after,
		})
	}
}

struct ApprovalDeadline {
	wall: Duration,
	monotonic: Instant,
	anchor: ClockSample,
}

impl ApprovalDeadline {
	fn at(clock: ClockSample, original: NonZeroU64) -> Result<Self, AuthorityError> {
		let wall = Duration::from_secs(original.get());
		let remaining = wall.checked_sub(clock.wall).ok_or(AuthorityError::Clock)?;
		let monotonic = clock
			.before
			.checked_add(remaining)
			.ok_or(AuthorityError::Clock)?;
		if clock.after < clock.before || clock.after >= monotonic {
			return Err(AuthorityError::Clock);
		}
		Ok(Self {
			wall,
			monotonic,
			anchor: clock,
		})
	}

	fn check(&self, clock: ClockSample, last: ClockSample) -> Result<(), AuthorityError> {
		if clock.before < last.after
			|| clock.after < clock.before
			|| clock.wall < last.wall
			|| clock.wall >= self.wall
			|| clock.after >= self.monotonic
		{
			return Err(AuthorityError::Clock);
		}
		Ok(())
	}
}
