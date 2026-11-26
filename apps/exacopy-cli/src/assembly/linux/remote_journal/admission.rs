use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_journal::OwnerProfileId;
use exacopy_journal::remote_download::qualification::RemoteQualificationRouteClass;
use exacopy_journal::remote_download::{
	RemoteBootstrapTrust, RemoteDownloadDurability, RemoteDownloadOwner, RemoteDownloadOwnerRecord,
	RemoteDownloadRoute, RemoteDownloadScope, RemoteScopeDigest,
};
use exacopy_platform::linux::{DestinationRoot, RemoteDestinationEligibility};
use exacopy_transfer::remote_metadata::ApprovedSftpMetadata;

use super::{Error, record_identity};
use exacopy_transfer::remote_finalization::RemotePublicationAuthority;

#[derive(Clone, Copy)]
pub(in crate::assembly::linux) enum OwnerDialect {
	EmbeddedV1,
	ResolvedDirect,
	AbsoluteEmbedded,
	AbsoluteResolvedDirect,
}

impl OwnerDialect {
	fn select(route: RemoteDownloadRoute, root: SftpPathRoot) -> Result<Self, Error> {
		match (route, root) {
			(RemoteDownloadRoute::EmbeddedWireGuard { .. }, SftpPathRoot::AccountRelative) => {
				Ok(Self::EmbeddedV1)
			}
			(RemoteDownloadRoute::ResolvedDirect { .. }, SftpPathRoot::AccountRelative) => {
				Ok(Self::ResolvedDirect)
			}
			(RemoteDownloadRoute::EmbeddedWireGuard { .. }, SftpPathRoot::Absolute) => {
				Ok(Self::AbsoluteEmbedded)
			}
			(RemoteDownloadRoute::ResolvedDirect { .. }, SftpPathRoot::Absolute) => {
				Ok(Self::AbsoluteResolvedDirect)
			}
			_ => Err(Error::UnsupportedRoute),
		}
	}

	const fn qualification_route(self) -> RemoteQualificationRouteClass {
		match self {
			Self::EmbeddedV1 | Self::AbsoluteEmbedded => {
				RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1
			}
			Self::ResolvedDirect | Self::AbsoluteResolvedDirect => {
				RemoteQualificationRouteClass::DirectPinnedTcpV1
			}
		}
	}

	pub(in crate::assembly::linux) fn sign(
		self,
		manifest: RemoteDownloadOwner,
		key: &SigningKey,
	) -> Result<RemoteDownloadOwnerRecord, Error> {
		Ok(match self {
			Self::EmbeddedV1 => RemoteDownloadOwnerRecord::sign(manifest, key)?,
			Self::ResolvedDirect => RemoteDownloadOwnerRecord::sign_resolved_direct(manifest, key)?,
			Self::AbsoluteEmbedded | Self::AbsoluteResolvedDirect => {
				RemoteDownloadOwnerRecord::sign_absolute_path(manifest, key)?
			}
		})
	}

	pub(in crate::assembly::linux) fn decode(
		self,
		bytes: &[u8],
		profile: OwnerProfileId,
		key: &VerifyingKey,
	) -> Result<RemoteDownloadOwnerRecord, Error> {
		Ok(match self {
			Self::EmbeddedV1 => RemoteDownloadOwnerRecord::decode(bytes, profile, key)?,
			Self::ResolvedDirect => {
				RemoteDownloadOwnerRecord::decode_resolved_direct(bytes, profile, key)?
			}
			Self::AbsoluteEmbedded | Self::AbsoluteResolvedDirect => {
				RemoteDownloadOwnerRecord::decode_absolute_path(bytes, profile, key)?
			}
		})
	}

	pub(in crate::assembly::linux) fn trust<'owner>(
		self,
		owner: &'owner RemoteDownloadOwnerRecord,
		profile: OwnerProfileId,
		key: &'owner VerifyingKey,
	) -> Result<RemoteBootstrapTrust<'owner>, Error> {
		Ok(match self {
			Self::EmbeddedV1 => RemoteBootstrapTrust::new(owner, profile, key)?,
			Self::ResolvedDirect => RemoteBootstrapTrust::new_resolved_direct(owner, profile, key)?,
			Self::AbsoluteEmbedded | Self::AbsoluteResolvedDirect => {
				RemoteBootstrapTrust::new_absolute_path(owner, profile, key)?
			}
		})
	}
}

/// App-owned, independently authenticated current grant for an exact scoped request.
pub(in crate::assembly::linux) trait CurrentGrant {
	fn recheck(&self, scope: RemoteScopeDigest) -> Result<[u8; 32], Error>;
}

pub(in crate::assembly::linux) trait CurrentQualification {
	fn recheck(
		&self,
		root: &DestinationRoot,
		route: RemoteQualificationRouteClass,
	) -> Result<[u8; 32], Error>;
}

// Supply the route class selected by the same verifier that produced the native projection.
impl CurrentQualification
	for (
		RemoteQualificationRouteClass,
		RemoteDestinationEligibility<'_>,
	)
{
	fn recheck(
		&self,
		root: &DestinationRoot,
		route: RemoteQualificationRouteClass,
	) -> Result<[u8; 32], Error> {
		if self.0 != route {
			return Err(Error::UnsupportedRoute);
		}
		self.1.recheck_for(root).map_err(Error::Qualification)?;
		Ok(self.1.qualification_digest())
	}
}

/// Holds the app's current authority selected independently of any job or journal bytes.
#[derive(Clone, Copy)]
pub(in crate::assembly::linux) struct RemoteActivation<'root> {
	pub(in crate::assembly::linux) root: &'root DestinationRoot,
	pub(in crate::assembly::linux) scope: &'root RemoteDownloadScope,
	pub(in crate::assembly::linux) dialect: OwnerDialect,
	scope_digest: RemoteScopeDigest,
	grant: &'root dyn CurrentGrant,
	qualification: &'root dyn CurrentQualification,
	pub(in crate::assembly::linux) grant_digest: [u8; 32],
	pub(in crate::assembly::linux) qualification_digest: [u8; 32],
}

impl<'root> RemoteActivation<'root> {
	pub(in crate::assembly::linux) fn admit(
		root: &'root DestinationRoot,
		scope: &'root RemoteDownloadScope,
		policy: ApprovedSftpMetadata,
		grant: &'root dyn CurrentGrant,
		qualification: &'root dyn CurrentQualification,
	) -> Result<Self, Error> {
		let dialect = OwnerDialect::select(scope.source.route(), scope.source.path_root())?;
		policy
			.verify_recorded(scope.metadata_policy)
			.map_err(Error::Metadata)?;
		if scope.requested_durability != RemoteDownloadDurability::ProcessCrash {
			return Err(Error::Binding);
		}
		let scope_digest = scope.digest()?;
		let grant_digest = grant.recheck(scope_digest)?;
		let qualification_digest = qualification.recheck(root, dialect.qualification_route())?;
		if grant_digest == [0; 32] || qualification_digest == [0; 32] {
			return Err(Error::Binding);
		}
		Ok(Self {
			root,
			scope,
			dialect,
			scope_digest,
			grant,
			qualification,
			grant_digest,
			qualification_digest,
		})
	}

	pub(in crate::assembly::linux) fn publication_authority(self) -> RemotePublicationAuthority {
		RemotePublicationAuthority {
			scope: self.scope_digest,
			grant: self.grant_digest,
			qualification: self.qualification_digest,
			parent: record_identity(self.root.identity()),
		}
	}

	pub(in crate::assembly::linux) fn recheck(self) -> Result<(), Error> {
		if self.grant.recheck(self.scope_digest)? != self.grant_digest
			|| self
				.qualification
				.recheck(self.root, self.dialect.qualification_route())?
				!= self.qualification_digest
		{
			return Err(Error::Binding);
		}
		Ok(())
	}
}
