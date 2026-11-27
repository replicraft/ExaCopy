//! Live invocation consent, independently selected from archived commitments.

#[cfg(test)]
use std::sync::PoisonError;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use exacopy_endpoint::ReadView;
use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::remote_download::witness::WitnessRetentionCommitment;
use exacopy_journal::remote_download::{
	RemoteDownloadContext, RemoteDownloadOwnerRecord, RemoteDownloadScope, RemoteScopeDigest,
};
use exacopy_platform::linux::{RecoveryWriteLease, RetainedPrefixRead, RetainedPrefixSelection};

use super::remote_download::{RemoteGrant, WitnessDeadline};

/// Private projection of two separately validated explicit user arguments.
pub(crate) struct ExplicitWitnessSelection(());

impl ExplicitWitnessSelection {
	pub(crate) fn select(verified_prefix: bool, allow_retention: bool) -> Option<Self> {
		(verified_prefix && allow_retention).then_some(Self(()))
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BoundWitnessStage<'name> {
	pub(super) context: RemoteDownloadContext,
	pub(super) scope: RemoteScopeDigest,
	pub(super) job: LinuxFileIdentity,
	pub(super) retained: RetainedPrefixSelection<'name>,
	pub(super) adopted_extent: u64,
	pub(super) source_extent: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ConsentRefusal {
	Binding,
	Clock,
	Revoked,
	Grant,
}

/// Both are independently selected through the authenticated local profile.
pub(super) struct SelectedWitnessOwner<'selection> {
	pub(super) owner: &'selection RemoteDownloadOwnerRecord,
	pub(super) approved_scope: &'selection RemoteDownloadScope,
}

pub(super) struct WitnessRetentionApproval<'grant, 'name> {
	grant: &'grant RemoteGrant,
	selection: BoundWitnessStage<'name>,
	commitment: WitnessRetentionCommitment,
	deadline: WitnessDeadline,
	state: Mutex<ConsentState>,
}

#[derive(Default)]
struct ConsentState {
	revoked: bool,
	last_wall: Option<Duration>,
}

#[must_use]
pub(in crate::assembly::linux) struct WitnessMutationGuard<'approval> {
	// Release the narrower guard first.
	_approval: MutexGuard<'approval, ConsentState>,
	_grant: MutexGuard<'approval, bool>,
	invocation: &'approval RemoteGrant,
	deadline: WitnessDeadline,
}

impl<'grant, 'name> WitnessRetentionApproval<'grant, 'name> {
	/// Admits the owner selected by protected runtime configuration under the actual job lease.
	/// The application resolves `selection` from the independent clean journal and request.
	pub(super) fn admit(
		_: ExplicitWitnessSelection,
		approved: SelectedWitnessOwner<'_>,
		lease: &RecoveryWriteLease<'_>,
		reader: &RetainedPrefixRead<'_>,
		selection: BoundWitnessStage<'name>,
		grant: &'grant RemoteGrant,
		grant_digest: [u8; 32],
	) -> Result<Self, ConsentRefusal> {
		let SelectedWitnessOwner {
			owner,
			approved_scope,
		} = approved;
		let manifest = owner.manifest();
		let job = lease.job().identity();
		let actual_job = LinuxFileIdentity::new(job.device(), job.inode());
		let parent = lease.job().destination_identity();
		let actual_parent = LinuxFileIdentity::new(parent.device(), parent.inode());
		if !reader.matches_lease(lease)
			|| reader.selection() != selection.retained
			|| reader.length() != selection.adopted_extent
			|| selection.adopted_extent > selection.source_extent
			|| selection.source_extent > approved_scope.maximum_extent.get()
			|| reader.recheck_observation().is_err()
			|| manifest.job_directory != actual_job
			|| manifest.scope.destination.parent() != actual_parent
			|| selection.job != actual_job
			|| &manifest.scope != approved_scope
			|| selection.scope
				!= approved_scope
					.digest()
					.map_err(|_| ConsentRefusal::Binding)?
			|| selection.context.owner != owner.digest()
			|| selection.context.job != manifest.job
			|| selection.context.entry != manifest.scope.entry
			|| selection.retained.target.as_bytes() != manifest.scope.destination.target()
		{
			return Err(ConsentRefusal::Binding);
		}
		if !grant
			.issue_witness(selection.scope, grant_digest)
			.map_err(|_| ConsentRefusal::Grant)?
		{
			return Err(ConsentRefusal::Revoked);
		}
		let deadline = grant.witness_deadline().ok_or(ConsentRefusal::Clock)?;
		let observed = deadline.check(None).ok_or(ConsentRefusal::Clock)?;
		let commitment = WitnessRetentionCommitment::measure(
			selection.context,
			selection.scope,
			grant_digest,
			deadline.wall_seconds(),
		)
		.map_err(|_| ConsentRefusal::Binding)?;
		Ok(Self {
			grant,
			selection,
			commitment,
			deadline,
			state: Mutex::new(ConsentState {
				revoked: false,
				last_wall: Some(observed),
			}),
		})
	}

	/// Historical signed projection produced only from a live admitted approval.
	pub(super) const fn commitment(&self) -> WitnessRetentionCommitment {
		self.commitment
	}

	/// Irreversibly stops this approval while retaining its archival projection.
	#[cfg(test)]
	pub(super) fn revoke(&self) {
		self.state
			.lock()
			.unwrap_or_else(PoisonError::into_inner)
			.revoked = true;
	}

	/// Enters the exact original grant then the witness approval for one effect.
	/// The caller finishes physical probes beforehand. A still-live data effect
	/// takes its concrete route guard last. The returned locks never cross an await.
	pub(super) fn enter(
		&self,
		grant: &RemoteGrant,
		selection: BoundWitnessStage<'_>,
	) -> Result<WitnessMutationGuard<'_>, ConsentRefusal> {
		if !std::ptr::eq(self.grant, grant) || self.selection != selection {
			return Err(ConsentRefusal::Binding);
		}
		let grant = self
			.grant
			.enter(selection.scope, self.commitment.base_grant_digest)
			.map_err(|_| ConsentRefusal::Grant)?;
		let mut state = self.state.lock().map_err(|_| ConsentRefusal::Revoked)?;
		if state.revoked {
			return Err(ConsentRefusal::Revoked);
		}
		let Some(now) = self.deadline.check(state.last_wall) else {
			state.revoked = true;
			return Err(ConsentRefusal::Clock);
		};
		state.last_wall = Some(now);
		Ok(WitnessMutationGuard {
			_approval: state,
			_grant: grant,
			invocation: self.grant,
			deadline: self.deadline,
		})
	}
}

impl WitnessMutationGuard<'_> {
	pub(in crate::assembly::linux) fn observed_wall_seconds(&self) -> Option<u64> {
		self._approval.last_wall.map(|time| time.as_secs())
	}

	pub(in crate::assembly::linux) fn matches_invocation(&self, expected: &RemoteGrant) -> bool {
		std::ptr::eq(self.invocation, expected)
	}

	pub(in crate::assembly::linux) fn recheck_locked(&mut self) -> bool {
		let Some(now) = self.deadline.check(self._approval.last_wall) else {
			self._approval.revoked = true;
			return false;
		};
		self._approval.last_wall = Some(now);
		true
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Mutex;
	use std::time::{Duration, Instant};

	use exacopy_endpoint::UnixComponent;
	use exacopy_endpoint::linux_job::JobFileIdentity;
	use exacopy_journal::{JournalEntryId, JournalJobId, OwnerDigest};

	use super::{
		BoundWitnessStage, ConsentRefusal, ConsentState, ExplicitWitnessSelection,
		LinuxFileIdentity, RemoteDownloadContext, RemoteGrant, RemoteScopeDigest,
		RetainedPrefixSelection, WitnessRetentionApproval, WitnessRetentionCommitment,
	};

	#[test]
	fn explicit_strategy_without_explicit_retention_is_never_consent() {
		assert!(ExplicitWitnessSelection::select(false, false).is_none());
		assert!(ExplicitWitnessSelection::select(false, true).is_none());
		assert!(ExplicitWitnessSelection::select(true, false).is_none());
		assert!(ExplicitWitnessSelection::select(true, true).is_some());
	}

	#[test]
	fn approval_is_bound_to_the_original_grant_instance_and_revokes_permanently() {
		let scope = RemoteScopeDigest::from_bytes([0x71; 32]);
		let digest = [0x72; 32];
		let end = Instant::now() + Duration::from_secs(60);
		let original = RemoteGrant::new(scope, digest, end).unwrap();
		let replacement = RemoteGrant::new(scope, digest, end).unwrap();
		let selection = BoundWitnessStage {
			context: RemoteDownloadContext {
				owner: OwnerDigest::from_bytes([0x73; 32]),
				job: JournalJobId::from_bytes([
					0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67,
					0x89, 0xab, 0xcd,
				])
				.unwrap(),
				entry: JournalEntryId::from_bytes([0x74; 16]),
			},
			scope,
			job: LinuxFileIdentity::new(7, 9),
			retained: RetainedPrefixSelection {
				stage: UnixComponent::new(b"stage-name").unwrap(),
				target: UnixComponent::new(b"target-name").unwrap(),
				directory: JobFileIdentity {
					device: 7,
					inode: 10,
				},
				file: JobFileIdentity {
					device: 7,
					inode: 11,
				},
			},
			adopted_extent: 21,
			source_extent: 30,
		};
		assert!(original.issue_witness(scope, digest).unwrap());
		// This control begins below native owner admission to isolate the guard.
		let deadline = original.witness_deadline().unwrap();
		let approval = WitnessRetentionApproval {
			grant: &original,
			selection,
			deadline,
			commitment: WitnessRetentionCommitment::measure(
				selection.context,
				scope,
				digest,
				deadline.wall_seconds(),
			)
			.unwrap(),
			state: Mutex::new(ConsentState::default()),
		};
		assert!(matches!(
			approval.enter(&replacement, selection),
			Err(ConsentRefusal::Binding)
		));
		assert!(matches!(
			approval.enter(
				&original,
				BoundWitnessStage {
					adopted_extent: 22,
					..selection
				}
			),
			Err(ConsentRefusal::Binding)
		));
		{
			let mut guard = approval.enter(&original, selection).unwrap();
			assert!(guard.recheck_locked());
		}
		approval.revoke();
		assert!(!original.issue_witness(scope, digest).unwrap());
		assert!(matches!(
			approval.enter(&original, selection),
			Err(ConsentRefusal::Revoked)
		));
	}
}
