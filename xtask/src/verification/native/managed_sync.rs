use std::path::Path;

use cargo_metadata::Package;

use super::{Case, CaseKind, Fixture, Profile};
use crate::finding::Findings;

const OWNER: &str = "exacopy-cli";
const MANIFEST: &str = "verification/managed_sync_production/fixture.toml";
const TARGET: &str = "linux_managed_sync_production";
const SOURCE: &str = "tests/linux_managed_sync_production.rs";
const SELECTOR: &str = "production_managed_init_then_preview_exact_p063_history";

pub(super) const FEATURE: &str = "experimental-linux-managed-sync";
const PREPARED_FEATURE: &str = "experimental-linux-public-apply";

pub(super) fn check(
	package: &Package,
	manifest: &Path,
	path: &Path,
	fixture: &Fixture,
	findings: &mut Findings,
) -> bool {
	let valid = matches_fixture(
		package.name.as_str(),
		manifest,
		fixture.profile,
		&fixture.cases,
	) && matches_prepared_component(
		fixture.profile,
		fixture.prepared_component_feature.as_deref(),
	) && fixture
		.prepared_component_feature
		.as_ref()
		.is_none_or(|feature| package.features.contains_key(feature));
	if !valid {
		findings.add(
			path,
			"managed-sync production fixture requires its exact application owner, manifest, one feature-bound case and exact prepared component feature",
		);
	}
	valid
}

fn matches_prepared_component(profile: Profile, feature: Option<&str>) -> bool {
	match profile {
		Profile::UnprivilegedWholeExt4ManagedSyncProduction => feature == Some(PREPARED_FEATURE),
		_ => feature.is_none(),
	}
}

fn matches_fixture(owner: &str, manifest: &Path, profile: Profile, cases: &[Case]) -> bool {
	let registered = manifest == Path::new(MANIFEST);
	if !matches!(profile, Profile::UnprivilegedWholeExt4ManagedSyncProduction) {
		return !registered;
	}
	registered
		&& manifest.as_os_str() == MANIFEST
		&& owner == OWNER
		&& matches!(cases, [case]
			if matches!(case.kind, CaseKind::RustIntegration)
				&& case.owner.is_none()
				&& case.test_target.as_deref() == Some(TARGET)
				&& case.source.as_os_str() == SOURCE
				&& case.selector == SELECTOR
				&& case.required_feature.as_deref() == Some(FEATURE)
				&& case.ignored)
}

#[cfg(test)]
mod tests;
