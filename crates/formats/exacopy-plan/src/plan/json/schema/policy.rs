use serde::{Deserialize, Serialize};

use super::super::super::{
	PlanConflict, PlanConsistency, PlanDurability, PlanFidelity, PlanPolicy, PlanPreservation,
	PlanPublication, PlanSourceRetirement, PlanStorage, PlanVerification,
};
use super::super::PlanJsonError;
use super::names::WireName;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Policy {
	preservation: String,
	conflict: String,
	verification: String,
	storage: String,
	publication: String,
	consistency: String,
	minimum_durability: String,
	fidelity: String,
	source_retirement: String,
	follow_symlinks: bool,
}

impl Policy {
	pub(super) fn as_policy(&self) -> Result<PlanPolicy, PlanJsonError> {
		if self.follow_symlinks {
			return Err(PlanJsonError::Unsupported);
		}
		Ok(PlanPolicy {
			preservation: PlanPreservation::parse(&self.preservation)?,
			conflict: PlanConflict::parse(&self.conflict)?,
			verification: PlanVerification::parse(&self.verification)?,
			storage: PlanStorage::parse(&self.storage)?,
			publication: PlanPublication::parse(&self.publication)?,
			consistency: PlanConsistency::parse(&self.consistency)?,
			minimum_durability: PlanDurability::parse(&self.minimum_durability)?,
			fidelity: PlanFidelity::parse(&self.fidelity)?,
			source_retirement: PlanSourceRetirement::parse(&self.source_retirement)?,
		})
	}
}

impl From<PlanPolicy> for Policy {
	fn from(policy: PlanPolicy) -> Self {
		Self {
			preservation: policy.preservation.name().to_owned(),
			conflict: policy.conflict.name().to_owned(),
			verification: policy.verification.name().to_owned(),
			storage: policy.storage.name().to_owned(),
			publication: policy.publication.name().to_owned(),
			consistency: policy.consistency.name().to_owned(),
			minimum_durability: policy.minimum_durability.name().to_owned(),
			fidelity: policy.fidelity.name().to_owned(),
			source_retirement: policy.source_retirement.name().to_owned(),
			follow_symlinks: false,
		}
	}
}
