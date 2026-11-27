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
UNIT_SOURCE = "src/linux/sync_preview/tests.rs"
NAMESPACE_SOURCE = "src/linux/sync_preview/namespaces/tests.rs"
NAMESPACE_PREFIX = "linux::sync_preview::namespaces::tests::"
TEST_NAMES = {
    "platform": (
        "linux::sync_preview::tests::a_bounded_directory_scan_cannot_certify_absence_when_exhausted",
        "linux::sync_preview::tests::matching_inode_cannot_substitute_a_different_raw_name",
        "linux::sync_preview::tests::recheck_rejects_absent_name_that_appears_and_rebound_root",
        "linux::sync_preview::tests::recheck_rejects_changed_bytes_and_required_metadata",
        "linux::sync_preview::tests::recheck_returns_ordered_fresh_present_stats_and_refuses_a_rebound_subject",
        "linux::sync_preview::tests::unsupported_and_aliased_subjects_never_become_absence",
        NAMESPACE_PREFIX + "accepts_only_fixed_kind_and_bounded_canonical_inode_text",
        NAMESPACE_PREFIX + "current_namespace_pins_are_read_only_and_match_fresh_observations",
        NAMESPACE_PREFIX + "distinguishes_missing_support_from_native_read_failure",
        NAMESPACE_PREFIX + "procfs_directory_cannot_be_used_as_a_namespace_object",
    ),
    "transfer": (
        "linux::sync_preview::tests::checks_both_limits_before_reading_and_refuses_incomplete_recheck",
    ),
}
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
            "source": NAMESPACE_SOURCE if selector.startswith(NAMESPACE_PREFIX) else UNIT_SOURCE,
            "ignored": False,
        }
        for family, selectors in TEST_NAMES.items()
        for selector in selectors
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
