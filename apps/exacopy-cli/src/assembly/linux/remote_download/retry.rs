use std::fmt;
use std::sync::Arc;

use exacopy_endpoint::connection_retry::ConnectionBinding;
use exacopy_platform::linux::RemoteDestinationEligibility;
use uuid::Uuid;

use crate::profile::kernel_random;

use super::super::remote_journal::{RemoteActivation, RemoteJobLease, RetryCaptureStamp};
use super::{
	Error, RemoteDownloadFailure, RemoteDownloadRequest, RemoteGrant, qualify_destination,
};

pub use super::super::remote_journal::RemoteRetryLease;

pub(crate) struct ReadyRetry<'held> {
	pub(super) lease: Box<RemoteRetryLease<'held>>,
	pub(super) eligibility: &'held RemoteDestinationEligibility<'held>,
}

/// Current-process retained observations after a failed read and confirmed route retirement.
///
/// The read-only pins carry no job lease across a wait. This type cannot establish
/// source equivalence or authorize a write, route or publication operation.
#[must_use]
pub struct RemoteRetryStamp {
	native: RetryCaptureStamp,
	grant: Arc<RemoteGrant>,
	connection: ConnectionBinding,
}

impl RemoteRetryStamp {
	pub(super) fn new(
		native: RetryCaptureStamp,
		grant: Arc<RemoteGrant>,
		connection: ConnectionBinding,
	) -> Self {
		Self {
			native,
			grant,
			connection,
		}
	}

	/// Identifies the previous fenced connection for failure attribution.
	#[must_use]
	pub const fn previous_connection(&self) -> ConnectionBinding {
		self.connection
	}

	/// Obtains a fresh exclusive observation lease for the original retained job.
	///
	/// Keep this lease during any subsequent admission. A link to the old
	/// source observation establishes only metadata mismatch rejection.
	///
	/// # Errors
	/// Refuses other grants, stale or ineligible native state, changed history,
	/// and insufficient capacity for a fresh preparation under the prior job.
	pub(crate) async fn with_lease<T>(
		self,
		request: &RemoteDownloadRequest<'_>,
		consume: impl for<'held> AsyncFnOnce(ReadyRetry<'held>) -> T,
	) -> Result<T, RemoteDownloadFailure> {
		if !std::ptr::eq(self.grant.as_ref(), request.grant) {
			return Err(RemoteDownloadFailure::ResumeAdmission(Error::Binding));
		}
		let (profile, verified) = qualify_destination(request)?;
		let native = RemoteDestinationEligibility::admit(request.root, Some(&verified))
			.map_err(Error::Qualification)?;
		let qualified = (request.qualification.scope.route, native);
		let activation = RemoteActivation::admit(
			request.root,
			request.scope,
			request.metadata,
			request.grant,
			&qualified,
		)?;
		let mut nonce = [0; 16];
		kernel_random(&mut nonce).map_err(Error::from)?;
		let name = format!("capture-{}", Uuid::from_bytes(nonce));
		let lease = RemoteJobLease::open_retry(
			&profile,
			request.job,
			activation,
			self.native,
			name.into_bytes().into_boxed_slice(),
			nonce,
		)
		.map_err(RemoteDownloadFailure::ResumeAdmission)?;
		Ok(consume(ReadyRetry {
			lease: Box::new(lease),
			eligibility: &qualified.1,
		})
		.await)
	}
}

impl fmt::Debug for RemoteRetryStamp {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RemoteRetryStamp").finish_non_exhaustive()
	}
}
