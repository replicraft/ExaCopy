use std::sync::Arc;

use exacopy_endpoint::connection_retry::{ConnectionBinding, RetryError};
use exacopy_transfer::remote_capture::SourceEpoch;

use super::route_lifetime::{HeldRouteEffect, RouteTask, observe_before};
use super::{RemoteGrant, RemoteRouteCloseError, SourceOwner};
use crate::assembly::linux::remote_witness_authority::WitnessMutationGuard;

/// One shutdown of the exact admitted route, held independently of the SFTP borrow.
#[must_use]
pub(in crate::assembly::linux) struct BoundRouteRetirement {
	task: Arc<RouteTask>,
	binding: ConnectionBinding,
	grant: Arc<RemoteGrant>,
}

/// Positive confirmation of the exact socket or owned embedded pump closing.
#[must_use]
pub(in crate::assembly::linux) struct RetiredBoundRoute {
	binding: ConnectionBinding,
	#[cfg(any(test, feature = "experimental-verified-prefix-resume"))]
	grant: Arc<RemoteGrant>,
}

impl RetiredBoundRoute {
	#[cfg(any(test, feature = "experimental-verified-prefix-resume"))]
	pub(in crate::assembly::linux) fn matches_invocation(&self, grant: &RemoteGrant) -> bool {
		std::ptr::eq(self.grant.as_ref(), grant)
	}

	pub(in crate::assembly::linux) const fn binding(&self) -> ConnectionBinding {
		self.binding
	}
}

impl BoundRouteRetirement {
	#[cfg(any(test, feature = "experimental-verified-prefix-resume"))]
	pub(in crate::assembly::linux) const fn binding(&self) -> ConnectionBinding {
		self.binding
	}

	/// Fences the exact admitted route and observes actual worker/transport close.
	pub(in crate::assembly::linux) async fn finish(
		self,
		source_epoch: SourceEpoch,
	) -> Result<RetiredBoundRoute, RemoteRouteCloseError> {
		if self.binding.source_epoch() != source_epoch {
			return Err(RemoteRouteCloseError::Unobserved);
		}
		self.task.stop();
		self.confirm().await?;
		Ok(RetiredBoundRoute {
			binding: self.binding,
			#[cfg(any(test, feature = "experimental-verified-prefix-resume"))]
			grant: Arc::clone(&self.grant),
		})
	}

	async fn confirm(&self) -> Result<(), RemoteRouteCloseError> {
		observe_before(
			tokio::time::Instant::from_std(self.grant.deadline()),
			self.task.join(),
		)
		.await
		.unwrap_or(Err(RemoteRouteCloseError::Unobserved))
	}
}

#[must_use]
pub(in crate::assembly::linux) struct WitnessRouteGuard<'route, 'approval> {
	// Field order releases route before approval and grant.
	_route: HeldRouteEffect<'route>,
	_approval: WitnessMutationGuard<'approval>,
}

impl BoundRouteRetirement {
	pub(in crate::assembly::linux) fn enter_capture<'route, 'approval>(
		&'route self,
		binding: ConnectionBinding,
		mut approval: WitnessMutationGuard<'approval>,
	) -> Result<WitnessRouteGuard<'route, 'approval>, RetryError> {
		if self.binding != binding || !approval.matches_invocation(&self.grant) {
			return Err(RetryError::StaleAdmission);
		}
		let route = self
			.task
			.enter_after_approval()
			.ok_or(RetryError::StaleWork)?;
		if std::time::Instant::now() >= self.grant.deadline() || !approval.recheck_locked() {
			return Err(RetryError::StaleWork);
		}
		Ok(WitnessRouteGuard {
			_route: route,
			_approval: approval,
		})
	}
}

impl Drop for BoundRouteRetirement {
	fn drop(&mut self) {
		self.task.stop();
	}
}

impl SourceOwner<'_> {
	pub(in crate::assembly::linux) fn prepare_retirement(
		&mut self,
		binding: ConnectionBinding,
	) -> Result<BoundRouteRetirement, RetryError> {
		if self.retirement_issued {
			return Err(RetryError::StaleWork);
		}
		self.check_binding(binding)?;
		self.retirement_issued = true;
		Ok(BoundRouteRetirement {
			task: Arc::clone(&self.transport),
			binding,
			grant: Arc::clone(&self.supervisor.grant),
		})
	}
}
