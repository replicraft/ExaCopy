use std::num::NonZeroU64;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use exacopy_endpoint::connection_retry::{PermanentFailure, RetryBlock, RetryError};
use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_platform::linux::{SelectedStreamPublicationAuthority, TargetStatus};
use exacopy_transfer::remote_finalization::{
	CurrentRemoteAuthority, RemoteAuthorityCheck, RemotePublicationFence,
};
use exacopy_transfer::remote_resume::TargetState;
use tokio::sync::Notify;

use super::super::remote_journal::{CurrentGrant, Error, RemoteActivation, component};

#[cfg(test)]
mod witness_clock;
#[cfg(test)]
pub(in crate::assembly::linux) use witness_clock::WitnessDeadline;

/// Foreground invoker authorization for a fixed request and monotonic lease.
/// The issuer checks the protected profile before constructing this capability.
/// Revocation and each admitted synchronous native effect use the same lock.
pub struct RemoteGrant {
	scope: RemoteScopeDigest,
	digest: [u8; 32],
	deadline: Instant,
	#[cfg(test)]
	wall_anchor: Option<witness_clock::ClockSample>,
	#[cfg(test)]
	witness_issued: std::sync::atomic::AtomicBool,
	active: Mutex<bool>,
	revoked: Notify,
}

impl RemoteGrant {
	/// Installs an independently admitted exact scope and finite deadline.
	/// Returns no grant for an already expired lease or an empty digest.
	#[must_use]
	pub fn new(scope: RemoteScopeDigest, digest: [u8; 32], deadline: Instant) -> Option<Self> {
		(digest != [0; 32] && deadline > Instant::now()).then(|| Self {
			scope,
			digest,
			deadline,
			#[cfg(test)]
			wall_anchor: witness_clock::ClockSample::now(),
			#[cfg(test)]
			witness_issued: std::sync::atomic::AtomicBool::new(false),
			active: Mutex::new(true),
			revoked: Notify::new(),
		})
	}

	/// Retires this lease. Waits for an already admitted synchronous effect to return.
	pub fn revoke(&self) {
		match self.active.lock() {
			Ok(mut active) => *active = false,
			Err(poisoned) => *poisoned.into_inner() = false,
		}
		self.revoked.notify_waiters();
	}

	pub(super) const fn deadline(&self) -> Instant {
		self.deadline
	}

	#[cfg(test)]
	pub(in crate::assembly::linux) fn issue_witness(
		&self,
		scope: RemoteScopeDigest,
		digest: [u8; 32],
	) -> Result<bool, Error> {
		let _guard = self.enter(scope, digest)?;
		Ok(!self
			.witness_issued
			.swap(true, std::sync::atomic::Ordering::Relaxed))
	}

	#[cfg(test)]
	pub(in crate::assembly::linux) fn witness_deadline(&self) -> Option<WitnessDeadline> {
		self.wall_anchor?.deadline(self.deadline)
	}

	pub(super) async fn wait_revoked(&self) {
		let notification = self.revoked.notified();
		tokio::pin!(notification);
		notification.as_mut().enable();
		if self.active.lock().is_ok_and(|active| *active) {
			notification.await;
		}
	}
	pub(super) fn remaining_from(&self, start: Instant) -> Result<Duration, RetryError> {
		self.deadline
			.checked_duration_since(start)
			.filter(|duration| !duration.is_zero())
			.ok_or(RetryError::Blocked(RetryBlock::GrantExpired))
	}

	pub(super) fn check_source(&self, scope: RemoteScopeDigest) -> Result<(), RetryError> {
		drop(self.source_lock(scope)?);
		Ok(())
	}

	pub(super) fn source_lock(
		&self,
		scope: RemoteScopeDigest,
	) -> Result<MutexGuard<'_, bool>, RetryError> {
		self.lock_current(scope, self.digest)
	}

	pub(in crate::assembly::linux) fn enter(
		&self,
		scope: RemoteScopeDigest,
		digest: [u8; 32],
	) -> Result<MutexGuard<'_, bool>, Error> {
		self.lock_current(scope, digest).map_err(Error::Grant)
	}

	fn lock_current(
		&self,
		scope: RemoteScopeDigest,
		digest: [u8; 32],
	) -> Result<MutexGuard<'_, bool>, RetryError> {
		if self.scope != scope || self.digest != digest {
			return Err(RetryError::StaleAdmission);
		}
		let revoked = RetryError::Blocked(RetryBlock::Permanent(PermanentFailure::GrantRevoked));
		let active = self.active.lock().map_err(|_| revoked)?;
		if !*active {
			return Err(revoked);
		}
		self.remaining_from(Instant::now())?;
		Ok(active)
	}
}

impl CurrentGrant for RemoteGrant {
	fn recheck(&self, scope: RemoteScopeDigest) -> Result<[u8; 32], Error> {
		drop(self.enter(scope, self.digest)?);
		Ok(self.digest)
	}
	fn enter_effect(
		&self,
		scope: RemoteScopeDigest,
		digest: [u8; 32],
	) -> Result<MutexGuard<'_, bool>, Error> {
		self.enter(scope, digest)
	}
}

pub(super) struct EffectAuthority<'root>(pub(super) RemoteActivation<'root>);

impl RemoteAuthorityCheck for EffectAuthority<'_> {
	type Error = Error;

	fn recheck(&mut self) -> Result<CurrentRemoteAuthority, Self::Error> {
		let active = self.0;
		active.recheck()?;
		let target = component(active.scope.destination.target())?;
		let target = match active.root.target_status(target)? {
			TargetStatus::Absent => TargetState::Absent,
			TargetStatus::Occupied => TargetState::Occupied,
		};
		Ok(CurrentRemoteAuthority {
			binding: active.publication_authority(),
			target,
		})
	}
}

pub(in crate::assembly::linux) fn native_authority(
	fence: RemotePublicationFence,
) -> Result<SelectedStreamPublicationAuthority, Error> {
	let active = fence.authority();
	let intent = fence.intent();
	Ok(SelectedStreamPublicationAuthority {
		owner: *fence.context().owner.as_bytes(),
		scope: *active.scope.as_bytes(),
		grant: active.grant,
		qualification: active.qualification,
		intent_digest: intent.digest(),
		intent_sequence: NonZeroU64::new(intent.sequence()).ok_or(Error::Binding)?,
	})
}

#[cfg(test)]
mod tests {
	use std::future::Future as _;
	use std::sync::mpsc;
	use std::time::Duration;

	use super::*;

	#[tokio::test]
	async fn wait_for_revocation_registers_before_checking_current_state() {
		let grant = RemoteGrant::new(
			RemoteScopeDigest::from_bytes([1; 32]),
			[2; 32],
			Instant::now() + Duration::from_secs(60),
		)
		.unwrap();
		let mut notification = std::pin::pin!(grant.wait_revoked());
		let registered = std::future::poll_fn(|cx| {
			std::task::Poll::Ready(notification.as_mut().poll(cx).is_pending())
		})
		.await;
		assert!(registered);
		grant.revoke();
		tokio::time::timeout(Duration::from_secs(1), notification)
			.await
			.expect("already registered waiter receives revocation");
		tokio::time::timeout(Duration::from_secs(1), grant.wait_revoked())
			.await
			.expect("waiter started after revocation does not wait");
	}

	#[test]
	fn revocation_serializes_behind_the_exact_native_gate_guard() {
		let scope = RemoteScopeDigest::from_bytes([1; 32]);
		let digest = [2; 32];
		assert!(RemoteGrant::new(scope, digest, Instant::now()).is_none());
		let grant =
			RemoteGrant::new(scope, digest, Instant::now() + Duration::from_secs(60)).unwrap();
		assert!(grant.enter(scope, [3; 32]).is_err());
		let renamed = grant.enter(scope, digest).unwrap();
		std::thread::scope(|scope| {
			let (entering, attempts_revoke) = mpsc::sync_channel(0);
			let (retired, revoked) = mpsc::channel();
			let grant = &grant;
			scope.spawn(move || {
				entering.send(()).unwrap();
				grant.revoke();
				retired.send(()).unwrap();
			});
			attempts_revoke.recv().unwrap();
			assert!(matches!(revoked.try_recv(), Err(mpsc::TryRecvError::Empty)));
			drop(renamed);
			revoked.recv().unwrap();
		});
		assert!(grant.enter(scope, digest).is_err());
	}
}
