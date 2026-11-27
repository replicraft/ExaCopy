//! Captures historical comparison inputs from the selected foreground invocation.

use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::JournalJobId;
use exacopy_journal::remote_download::RemoteScopeDigest;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;

use crate::assembly::linux::{ArchivedWitnessedSelection, OriginalWitnessResume};
use crate::remote_report::RemoteFailureKind as Failure;

/// Historical comparison facts, carrying no permission to continue an invocation.
pub(super) struct SelectionSeed {
	job: JournalJobId,
	owner_key: VerifyingKey,
	route: RemoteQualificationRouteClass,
	path_root: SftpPathRoot,
	scope: RemoteScopeDigest,
	op1_digest: [u8; 32],
	op2_digest: [u8; 32],
	base_grant_digest: [u8; 32],
}

impl SelectionSeed {
	/// The caller supplies the same digest used to construct this foreground grant.
	pub(super) fn capture(
		request: &OriginalWitnessResume<'_>,
		base_grant_digest: [u8; 32],
	) -> Result<Self, Failure> {
		if request.initial_v1_qualification != request.fresh_v1_qualification
			|| base_grant_digest == [0; 32]
		{
			return Err(Failure::Authorization);
		}
		Ok(Self {
			job: request.job,
			owner_key: request.profile.verification_key(),
			route: super::selection::route_class(request.scope.source.route())?,
			path_root: request.scope.source.path_root(),
			scope: request.scope.digest().map_err(|_| Failure::Authorization)?,
			op1_digest: request.initial_v1_qualification,
			op2_digest: *request.qualification.digest().as_bytes(),
			base_grant_digest,
		})
	}

	/// Called only after the original SDK returns an actual committed publication.
	pub(super) fn committed(
		self,
		committed: RemoteReplayBoundary,
		receipt_digest: [u8; 32],
	) -> ArchivedWitnessedSelection {
		ArchivedWitnessedSelection {
			job: self.job,
			owner_key: self.owner_key,
			route: self.route,
			path_root: self.path_root,
			scope: self.scope,
			op1_digest: self.op1_digest,
			op2_digest: self.op2_digest,
			base_grant_digest: self.base_grant_digest,
			committed,
			receipt_digest,
		}
	}
}
