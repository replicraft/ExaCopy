#!/usr/bin/env python3
"""Generate independent unsigned Plan JSON and canonical CBOR fixtures."""

import argparse
from base64 import b64encode
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
from uuid import UUID

BASE = Path(__file__).resolve().parent
MODULE = importlib.util.spec_from_file_location(
    "plan_body_reference", BASE.parent / "plan_body/reference.py"
)
reference = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(reference)

OPERATIONS = "copy move restore backup dedupe reclaim repair".split()
VIEWS = "live_observed file_stable tree_snapshot application_consistent".split()
PLATFORMS = "linux windows macos remote repository".split()
POLICY = (
    ("preservation", "preserve protected_replace protected_move explicit_reclaim"),
    ("conflict", "error skip rename protected-replace"),
    ("verification", "blake3_readback sha256_readback bytes"),
    ("storage", "independent shared-cow"),
    ("publication", "per_file new_tree"),
    ("consistency", "auto " + " ".join(VIEWS)),
    ("minimum_durability", "process_crash qualified_power_loss"),
    ("fidelity", "required-data native-strict portable"),
    ("source_retirement", "none quarantine"),
)


def date(value):
    if value is None:
        return None
    seconds, nanos = value
    utc = datetime.fromtimestamp(seconds, timezone.utc)
    fraction = ""
    if nanos:
        precision, scale = next(
            (digits, denominator) for digits, denominator in ((3, 1_000_000), (6, 1_000), (9, 1))
            if nanos % denominator == 0
        )
        fraction = f".{nanos // scale:0{precision}d}"
    return utc.isoformat(timespec="seconds").removesuffix("+00:00") + fraction + "Z"


def timestamp_vectors():
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    cases = (
        ("1969-12-31T23:59:59", "1", "Z"),
        ("1970-01-01T00:15:00", "12", "+00:30"),
        ("1970-01-01T00:00:00", "1234", "+00:00"),
        ("1970-01-01T00:00:00", "1234567", "-00:00"),
        ("0001-01-02T23:59:01", "000000001", "+23:59"),
        ("2000-02-29T23:00:00", "000001", "-02:00"),
        ("9999-12-31T00:00:59", "999999999", "-23:59"),
    )
    vectors = []
    for local, fraction, offset in cases:
        elapsed = datetime.fromisoformat(local + offset) - epoch
        seconds = elapsed.days * 86400 + elapsed.seconds
        nanos = int(fraction.ljust(9, "0"))
        vectors.append({
            "input": f"{local}.{fraction}{offset}",
            "seconds": seconds,
            "nanoseconds": nanos,
            "canonical": date((seconds, nanos)),
        })
    return (json.dumps(vectors, indent=2) + "\n").encode()


def uid(value):
    return str(UUID(bytes=value))


def atom(value):
    return None if value is None else b64encode(value).decode("ascii")


def identity(value):
    if value is None:
        return None
    return {
        "platform": PLATFORMS[value[0]],
        "volume_id_base64": atom(value[1]),
        "object_id_base64": atom(value[2]),
        "generation_base64": atom(value[3]),
    }


def view(value):
    return {
        "view_id": uid(value[0]),
        "root_id": uid(value[1]),
        "consistency": VIEWS[value[2]],
        "provider": value[3],
        "measurement_id": uid(value[4]),
        "source_identity": identity(value[5]),
        "observed_at": date(value[6]),
        "snapshot_token_digest": None if value[7] is None else value[7].hex(),
        "stable_until": date(value[8]),
    }


def page(value):
    assert value[1] == reference.PLAN_ENTRIES
    return {
        "page_id": value[0].hex(),
        "page_kind": "plan_entries",
        "encoded_bytes": str(value[2]),
        "entry_count": str(value[3]),
    }


def body(value):
    return {
        "schema_version": ".".join(map(str, value[0])),
        "plan_id": uid(value[1]),
        "operation": OPERATIONS[value[2]],
        "created_at": date(value[3]),
        "expires_at": date(value[4]),
        "source_roots": [uid(root) for root in value[5]],
        "destination_root": uid(value[6]),
        "entry_pages": list(map(page, value[7])),
        "policy": {
            name: options.split()[value[8][index]]
            for index, (name, options) in enumerate(POLICY)
        } | {"follow_symlinks": value[8][9]},
        "resource_limits": {
            "buffer_budget_bytes": str(value[9][0]),
            "io_inflight_max": value[9][1],
        },
        "approval_required": value[10],
        "source_views": list(map(view, value[11])),
        "required_grants": value[12],
        "estimated_working_bytes": str(value[13]),
        "conflict_count": str(value[14]),
        "entry_count": str(value[15]),
        "complete": value[16],
        "extensions": value[127],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    executable = args.hash.resolve()
    _, references, _ = reference.coherent_fixture_bundle(executable)
    for name, plan in reference.bodies(references):
        if plan[16]:
            plan[3] = [1_700_000_000, 123_456_789]
            plan[4] = [1_700_086_400, 0]
        canonical = reference.encode(plan)
        assert reference.decode(canonical) == plan
        digest = reference.digest(executable, reference.PLAN_DOMAIN + canonical)
        public = body(plan)
        if plan[16]:
            # An equivalent non-UTC spelling. The expected CBOR remains fixed.
            assert public["created_at"] == "2023-11-14T22:13:20.123456789Z"
            public["created_at"] = "2023-11-15t03:43:20.123456789+05:30"
        envelope = {"digest": digest.hex(), "body": public}
        payload = (json.dumps(envelope, indent=2, ensure_ascii=False) + "\n").encode()
        reference.emit(BASE / f"vectors/{name}.json", payload, args.write)
        reference.emit(BASE / f"vectors/{name}.body.cbor", canonical, args.write)
        print(name, len(payload), len(canonical), digest.hex())
    reference.emit(BASE / "vectors/timestamps.json", timestamp_vectors(), args.write)


if __name__ == "__main__":
    main()
