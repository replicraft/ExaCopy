//! Read-only planning of one Linux preserve-mode create-new copy.

use std::convert::Infallible;
use std::fmt;

use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_copy::{CopyDestinationView, TargetObservation};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_staging::StagingSource;
use exacopy_plan::{
	DocumentRef, PlanBody, PlanBodyFields, PlanConflict, PlanConsistency, PlanDurability,
	PlanEntriesPage, PlanEntry, PlanExtensions, PlanFidelity, PlanIdentityPlatform, PlanOperation,
	PlanPath, PlanPolicy, PlanPreservation, PlanPublication, PlanResourceLimits,
	PlanSourceIdentity, PlanSourceRetirement, PlanSourceView, PlanStorage, PlanVerification,
	PlanViewConsistency, UnixTimestamp, is_plan_id,
};
use uuid::Uuid;

use crate::{linux_staging::check_source, manifest};

mod error;

pub use error::PlanningError;

#[cfg(test)]
mod tests;

const LINUX_BASELINE_METADATA_POLICY: &[u8] = b"ExaCopy/metadata-policy/linux-baseline/v1\0";
pub(crate) const READ_CONTENT: &str = "read-content";
pub(crate) const CREATE_NEW: &str = "create-new";
pub(crate) const COPY_POLICY: PlanPolicy = PlanPolicy {
	preservation: PlanPreservation::Preserve,
	conflict: PlanConflict::Error,
	verification: PlanVerification::Blake3Readback,
	storage: PlanStorage::Independent,
	publication: PlanPublication::PerFile,
	consistency: PlanConsistency::LiveObserved,
	minimum_durability: PlanDurability::ProcessCrash,
	fidelity: PlanFidelity::RequiredData,
	source_retirement: PlanSourceRetirement::None,
};

/// Returns the registered digest of Linux baseline metadata policy v1.
/// The digest binds the policy identity. Live values are captured and
/// revalidated by the executor when applying that policy.
#[must_use]
pub fn linux_baseline_metadata_policy_digest() -> [u8; 32] {
	*blake3::hash(LINUX_BASELINE_METADATA_POLICY).as_bytes()
}

/// An exact basename beneath one caller-selected root.
#[derive(Clone, Copy, Debug)]
pub struct PlanSelection<'name> {
	/// Opaque alias for the independently selected root.
	pub root_id: Uuid,
	/// Original Unix basename bytes.
	pub component: UnixComponent<'name>,
}

impl<'name> PlanSelection<'name> {
	fn path(self) -> PlanPath<'name> {
		PlanPath {
			root_id: self.root_id,
			basename: self.component.as_bytes(),
		}
	}
}

/// Caller-selected identifiers, names and observation timestamp.
#[derive(Clone, Copy, Debug)]
pub struct CreateNewRequest<'name> {
	/// RFC UUIDv7 of the public plan.
	pub plan_id: Uuid,
	/// Independent non-nil identifier for the single planned entry.
	pub entry_id: Uuid,
	/// Independent non-nil identifier for the selected live source view.
	pub source_view_id: Uuid,
	/// Independent non-nil identifier for the source-content measurement.
	pub measurement_id: Uuid,
	/// Exact selected source basename and its independently bound root alias.
	pub source: PlanSelection<'name>,
	/// Exact intended new basename and its independently bound root alias.
	pub destination: PlanSelection<'name>,
	/// Wall-clock timestamp captured by the caller for the live planning observation.
	pub observed_at: UnixTimestamp,
}

/// Canonical public Plan v1 body and its single immutable PlanEntries leaf.
///
/// A plan records historical observations and requests independently
/// authorized create-new effects. It carries no authority to create an entry.
pub struct PlannedCopy {
	body: Vec<u8>,
	digest: [u8; 32],
	page: Vec<u8>,
	page_ref: DocumentRef,
}

impl fmt::Debug for PlannedCopy {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PlannedCopy")
			.field("body_bytes", &self.body.len())
			.field("page_bytes", &self.page.len())
			.finish_non_exhaustive()
	}
}

impl PlannedCopy {
	/// Returns the canonical unsigned public Plan v1 body.
	#[must_use]
	pub fn canonical_body(&self) -> &[u8] {
		&self.body
	}

	/// Returns the public Plan body digest for these exact canonical bytes.
	#[must_use]
	pub const fn digest(&self) -> [u8; 32] {
		self.digest
	}

	/// Returns the canonical PlanEntries leaf bound by the public body.
	#[must_use]
	pub fn canonical_page(&self) -> &[u8] {
		&self.page
	}

	/// Returns the derived reference to this exact page.
	#[must_use]
	pub const fn page_ref(&self) -> DocumentRef {
		self.page_ref
	}
}

/// Measures one selected source and constructs its public create-new plan.
///
/// The caller provides only read-only source selection and destination
/// observation. The source capability must revalidate the original name,
/// its held observation and EOF. The caller can exclude a held source
/// identity, such as an application-owned credential. The destination observation must never
/// traverse the selected final component or read its contents.
///
/// # Errors
/// Rejects invalid IDs and bounds, occupied targets, unavailable observations,
/// source metadata outside the copy policy, or incomplete measurement.
pub fn plan_create_new<'name, S, D>(
	request: CreateNewRequest<'name>,
	open_source: impl FnOnce(UnixComponent<'name>) -> Result<S, S::Error>,
	allow_source: impl FnOnce(S::Identity) -> bool,
	destination: &D,
	scratch: &mut [u8],
) -> Result<PlannedCopy, PlanningError<S::Error, D::Error>>
where
	S: StagingSource<Identity: Into<JobFileIdentity>>,
	D: CopyDestinationView + ?Sized,
{
	let limits = admit_request(request, scratch.len())?;
	check_target(destination, request.destination.component)?;
	let source = open_source(request.source.component).map_err(PlanningError::OpenSource)?;
	if !allow_source(source.identity()) {
		return Err(PlanningError::SourceForbidden);
	}
	check_source::<_, Infallible>(&source).map_err(PlanningError::SourcePolicy)?;
	let measured = manifest::measure(&source, scratch).map_err(PlanningError::Measure)?;
	check_target(destination, request.destination.component)?;
	check_source::<_, Infallible>(&source).map_err(PlanningError::SourcePolicy)?;
	encode(request, limits, source.identity().into(), measured)
}

fn admit_request<S, D>(
	request: CreateNewRequest<'_>,
	scratch: usize,
) -> Result<PlanResourceLimits, PlanningError<S, D>> {
	if !is_plan_id(request.plan_id)
		|| [
			request.entry_id,
			request.source_view_id,
			request.measurement_id,
			request.source.root_id,
			request.destination.root_id,
		]
		.iter()
		.any(Uuid::is_nil)
		|| request.source.path() == request.destination.path()
	{
		return Err(PlanningError::InvalidIdentity);
	}
	if scratch == 0 || scratch > MAX_SCRATCH_BYTES {
		return Err(PlanningError::InvalidBuffer);
	}
	let bytes = u64::try_from(scratch).map_err(|_| PlanningError::InvalidBuffer)?;
	PlanResourceLimits::new(bytes, 1).map_err(PlanningError::Body)
}

fn check_target<S, D: CopyDestinationView + ?Sized>(
	destination: &D,
	target: UnixComponent<'_>,
) -> Result<(), PlanningError<S, D::Error>> {
	match destination
		.observe_target(target)
		.map_err(PlanningError::ObserveTarget)?
	{
		TargetObservation::Absent => Ok(()),
		TargetObservation::Occupied => Err(PlanningError::Conflict),
	}
}

fn encode<S, D>(
	request: CreateNewRequest<'_>,
	limits: PlanResourceLimits,
	identity: JobFileIdentity,
	measurement: manifest::Measurement,
) -> Result<PlannedCopy, PlanningError<S, D>> {
	let device = identity.device.to_le_bytes();
	let inode = identity.inode.to_le_bytes();
	let source_identity = Some(PlanSourceIdentity {
		platform: PlanIdentityPlatform::Linux,
		volume_id: &device,
		object_id: &inode,
		generation: None,
	});
	let page = PlanEntriesPage::new(PlanEntry {
		entry_id: request.entry_id,
		source: request.source.path(),
		destination: request.destination.path(),
		source_view_id: request.source_view_id,
		source_identity,
		stream_length: measurement.length,
		stream_digest: measurement.digest,
		metadata_policy_digest: linux_baseline_metadata_policy_digest(),
		estimated_working_bytes: measurement.length,
	})
	.map_err(PlanningError::Page)?;
	let page_ref = page.document_ref();
	let plan = PlanBody::new(PlanBodyFields {
		plan_id: request.plan_id,
		operation: PlanOperation::Copy,
		created_at: request.observed_at,
		expires_at: None,
		source_roots: vec![request.source.root_id],
		destination_root: request.destination.root_id,
		entry_pages: vec![page_ref],
		policy: COPY_POLICY,
		resource_limits: limits,
		approval_required: true,
		source_views: vec![PlanSourceView {
			view_id: request.source_view_id,
			root_id: request.source.root_id,
			consistency: PlanViewConsistency::LiveObserved,
			provider: "linux-local",
			measurement_id: request.measurement_id,
			source_identity,
			observed_at: request.observed_at,
			snapshot_token_digest: None,
			stable_until: None,
		}],
		required_grants: vec![READ_CONTENT, CREATE_NEW],
		estimated_working_bytes: measurement.length,
		conflict_count: 0,
		entry_count: 1,
		complete: true,
		extensions: PlanExtensions::empty(),
	})
	.map_err(PlanningError::Body)?;
	Ok(PlannedCopy {
		digest: plan.digest(),
		body: plan.canonical_cbor().to_vec(),
		page: page.canonical_cbor(),
		page_ref,
	})
}
