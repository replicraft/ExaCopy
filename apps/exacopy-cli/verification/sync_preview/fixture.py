"""Bind the reviewed sync case inventory and target to the native fixture registry."""

import hashlib
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[4]
PACKAGE = "exacopy-cli"
DIRECTORY = "verification/sync_preview"
FIXTURE = f"{DIRECTORY}/fixture.toml"
PROFILE = "linux-unprivileged-tmpfs-sync-preview-v1"
TARGET = "x86_64-unknown-linux-gnu"
TOOLCHAIN = "1.100.0"
UNIT_OWNERS = {"platform": "exacopy-platform", "transfer": "exacopy-transfer"}
UNIT_ROOTS = {
    "platform": "crates/platform/exacopy-platform",
    "transfer": "crates/engines/exacopy-transfer",
}
PREFIX = "linux::sync_preview::"
UNIT_SOURCE = "src/linux/sync_preview/tests.rs"
NAMESPACE_SOURCE = "src/linux/sync_preview/namespaces/tests.rs"


UNIT_GROUPS = {
    "platform": (
        ("tests::", UNIT_SOURCE, (
            "a_bounded_directory_scan_cannot_certify_absence_when_exhausted",
            "matching_inode_cannot_substitute_a_different_raw_name",
            "recheck_rejects_absent_name_that_appears_and_rebound_root",
            "recheck_rejects_changed_bytes_and_required_metadata",
            "recheck_returns_ordered_fresh_present_stats_and_refuses_a_rebound_subject",
            "unsupported_and_aliased_subjects_never_become_absence",
        )),
        ("namespaces::tests::", NAMESPACE_SOURCE, (
            "accepts_only_fixed_kind_and_bounded_canonical_inode_text",
            "current_namespace_pins_are_read_only_and_match_fresh_observations",
            "distinguishes_missing_support_from_native_read_failure",
            "procfs_directory_cannot_be_used_as_a_namespace_object",
        )),
        ("tests::coverage::", "tests/unit/sync_preview.rs", (
            "selection_rejects_invalid_parent_paths_and_duplicate_root_names",
            "selection_rejects_symlinked_parents_and_children_and_retains_native_causes",
            "selection_refuses_procfs_as_an_unsupported_mount",
            "selection_and_recheck_keep_raw_names_ordered_and_preserve_both_files",
            "recheck_refuses_disappeared_linked_and_rebound_parents",
            "recheck_refuses_a_disappeared_or_symlinked_child_root",
            "recheck_rejects_changed_or_disappeared_unsupported_entries",
            "access_denial_remains_a_system_error_instead_of_a_changed_or_absent_entry",
            "typed_observation_refusals_explain_their_scope",
        )),
        ("history_scope::tests::", "tests/unit/sync_history_scope.rs", (
            "stable_live_pair_on_tmpfs_refuses_history_location_and_preserves_inputs",
            "changed_subject_refuses_history_before_the_mount_check",
            "changed_root_refuses_history_before_the_mount_check",
            "history_directory_requires_matching_live_identity_and_mounts",
        )),
        ("names::tests::", "tests/unit/preview_names.rs", (
            "a_regular_file_cannot_supply_a_directory_observation",
            "a_detached_directory_cannot_certify_absence",
        )),
        ("namespaces::tests::preview_namespaces::", "tests/unit/preview_namespaces.rs", (
            "recheck_refuses_stale_identity_for_either_live_namespace_pin",
            "namespace_link_observation_refuses_missing_wrong_kind_and_wrong_label",
        )),
    ),
    "transfer": (
        ("tests::", UNIT_SOURCE, (
            "checks_both_limits_before_reading_and_refuses_incomplete_recheck",
        )),
    ),
}
UNIT_CASES = {
    family: tuple(
        (f"{PREFIX}{module}{name}", source)
        for module, source, names in groups
        for name in names
    )
    for family, groups in UNIT_GROUPS.items()
}
TEST_NAMES = {family: tuple(name for name, _ in cases) for family, cases in UNIT_CASES.items()}
CASES = (
    "equal", "same_extent_divergent", "metadata_divergent",
    "one_sided", "both_absent", "different_spelling", "unsupported_link",
    "aliased_files", "oversized", "directory_cap", "unavailable_root",
    "explicit_no_history_required",
)


def expected_manifest():
    runner = f"{DIRECTORY}/qualify.py"
    cases = [
        {"kind": "command", "selector": name, "source": runner, "ignored": False}
        for name in CASES
    ]
    cases.extend(
        {
            "kind": "rust-unit", "owner": UNIT_OWNERS[family], "selector": selector,
            "source": source,
            "ignored": False,
        }
        for family, cases in UNIT_CASES.items()
        for selector, source in cases
    )
    return {
        "schema_version": 1, "id": "linux-sync-preview",
        "target": TARGET, "profile": PROFILE, "rust_toolchain": TOOLCHAIN,
        "runner": runner, "controls": f"{DIRECTORY}/test_qualify.py",
        "workflow": ".github/workflows/linux-sync-preview-qualification.yml",
        "result": "result.json", "case": cases,
    }


def read_exact(path):
    if not path.is_absolute() or path.resolve() != path or not path.is_file():
        raise ValueError("fixture binding requires a canonical, non-symlinked file")
    with path.open("rb") as source:
        data = source.read(64 * 1024 + 1)
    if len(data) > 64 * 1024:
        raise ValueError("fixture binding exceeds its input budget")
    return data


def unit_source_fingerprints():
    return {
        family: {
            source: hashlib.sha256(read_exact(ROOT / UNIT_ROOTS[family] / source)).hexdigest()
            for source in sorted({source for _, source in cases})
        }
        for family, cases in UNIT_CASES.items()
    }


def bind_fixture(manifest_path=ROOT / "apps" / PACKAGE / FIXTURE,
                 owners_path=ROOT / "specs/verification/owners.toml"):
    manifest_bytes = read_exact(manifest_path)
    manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    if (
        manifest != expected_manifest()
        or type(manifest["schema_version"]) is not int
        or any(case["ignored"] is not False for case in manifest["case"])
    ):
        raise ValueError("native fixture manifest disagrees with the reviewed sync profile")

    owners_bytes = read_exact(owners_path)
    owners = tomllib.loads(owners_bytes.decode("utf-8"))
    fixtures = owners.get("native_fixtures")
    registered = fixtures.get(PACKAGE, []) if isinstance(fixtures, dict) else []
    if type(owners.get("schema_version")) is not int or owners["schema_version"] != 1 or (
        not isinstance(registered, list) or registered.count(FIXTURE) != 1
    ):
        raise ValueError("native sync fixture is not registered exactly once under exacopy-cli")

    return {
        "fixture_id": manifest["id"], "profile": PROFILE, "target": TARGET,
        "rust_toolchain": TOOLCHAIN,
        "fixture_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "native_owners_sha256": hashlib.sha256(owners_bytes).hexdigest(),
    }
