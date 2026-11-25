#!/usr/bin/env python3
"""Check tracked requirements trace links and optionally the local baseline."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "docs/specs/requirements/local.v1.toml"
DESIGN_INVENTORIES = ("requirements", "acceptance-cases", "invariants", "proof-obligations")
TEST_LEVELS = {"test", "simulation", "native", "process-kill", "policy"}
EVIDENCE_STATES = {
    "obligation": {"defined"},
    "test": {"defined"},
    "simulation": {"defined"},
    "native": {"defined", "blocked"},
    "process-kill": {"defined"},
    "policy": {"defined"},
    "fixture": {"defined"},
    "fuzz": {"defined"},
    "configuration": {"defined"},
    "documentation": {"reported"},
    "reference": {"retained"},
    "benchmark": {"retained"},
}


def check_ids(values, prefix):
    if not values or len(values) != len(set(values)):
        raise ValueError(f"expected distinct {prefix} IDs")
    if any(not re.fullmatch(rf"{prefix}-[0-9]{{3}}", value) for value in values):
        raise ValueError(f"invalid {prefix} identifier")


def check_evidence(item, owners):
    level, state = item["level"], item["state"]
    if state not in EVIDENCE_STATES.get(level, set()):
        raise ValueError(f"invalid evidence level and state {level!r}, {state!r}")
    if state == "blocked" and not item.get("detail"):
        raise ValueError("blocked evidence requires a reason")

    path = ROOT / item["path"]
    if Path(item["path"]).is_absolute() or not path.resolve().is_relative_to(ROOT):
        raise ValueError(f"invalid repository path {item['path']}")
    if path.resolve().is_relative_to(ROOT / "docs/temp") or not path.is_file():
        raise ValueError(f"missing repository evidence path {item['path']}")
    owner = item["owner"]
    if owner not in owners and owner not in {"workspace", "reference tools"}:
        raise ValueError(f"unknown evidence owner {owner}")
    target = item.get("target")
    if level in TEST_LEVELS | {"fuzz", "obligation"}:
        if owner not in owners or not path.resolve().is_relative_to(owners[owner]):
            raise ValueError(f"{item['path']} must live under its evidence owner")
    if level in TEST_LEVELS:
        if not target or not re.search(rf"\bfn\s+{re.escape(target)}\s*\(", path.read_text()):
            raise ValueError(f"{item['path']} has no test function {target}")
    elif level == "obligation":
        if path != owners[owner] / "verification/obligations.toml":
            raise ValueError(f"{item['path']} is not the owner's obligation manifest")
        entries = tomllib.loads(path.read_text())["obligation"]
        if target not in {entry["id"] for entry in entries}:
            raise ValueError(f"{item['path']} has no implemented obligation {target}")
    elif state == "retained":
        record = json.loads(path.read_text())
        if not record.get("outcome") or not record.get("configuration"):
            raise ValueError(f"{item['path']} has no recorded outcome or configuration")


def check_pack(pack, fingerprints):
    inventories = {}
    for name in DESIGN_INVENTORIES:
        relative = f"inventories/{name}.json"
        raw = (pack / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != fingerprints[relative]:
            raise ValueError(f"baseline fingerprint mismatch for {relative}")
        inventories[name] = {row["id"]: row for row in json.loads(raw)}
    return inventories


def check_claim(claim, owners, inventories):
    status = claim["status"]
    if status not in {"implemented", "experimental", "specified"}:
        raise ValueError(f"invalid coverage status {status!r}")
    if not claim["scope"] or not claim["limits"]:
        raise ValueError("scope and limits must both be described")
    requirements = claim["requirement_ids"]
    acceptance = claim["acceptance_ids"]
    invariants = claim["invariant_ids"]
    check_ids(requirements, "R")
    check_ids(acceptance, "A")
    check_ids(invariants, "INV")
    # Baseline 2.1 registers one acceptance case per requirement with matching numbers.
    if acceptance != ["A" + requirement[1:] for requirement in requirements]:
        raise ValueError("acceptance IDs must follow their requirement IDs in baseline order")
    if inventories:
        for ids, inventory in (
            (requirements, "requirements"),
            (acceptance, "acceptance-cases"),
            (invariants, "invariants"),
        ):
            for identifier in ids:
                if identifier not in inventories[inventory]:
                    raise ValueError(f"unknown baseline identifier {identifier}")
        for requirement, case in zip(requirements, acceptance, strict=True):
            if case not in inventories["requirements"][requirement]["acceptance_ids"].split(";"):
                raise ValueError(f"baseline requirement {requirement} does not reference {case}")
            if requirement not in inventories["acceptance-cases"][case]["requirement_ids"].split(";"):
                raise ValueError(f"baseline acceptance {case} does not reference {requirement}")

    evidence = claim.get("evidence", [])
    if bool(evidence) != (status != "specified"):
        raise ValueError("implemented and experimental scopes need evidence links, specified scopes have none")
    seen = set()
    for item in evidence:
        key = (item["level"], item["path"], item.get("target"))
        if key in seen:
            raise ValueError(f"duplicate evidence link {key}")
        seen.add(key)
        check_evidence(item, owners)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, help="also verify IDs and hashes against this local pack root")
    arguments = parser.parse_args()

    try:
        trace = tomllib.loads(TRACE.read_text())
        if trace["schema_version"] != 1:
            raise ValueError("unsupported requirements trace version")
        fingerprints = trace["design_baseline"]["sha256"]
        if fingerprints.keys() != {f"inventories/{name}.json" for name in DESIGN_INVENTORIES}:
            raise ValueError("incomplete design inventory fingerprints")
        if any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in fingerprints.values()):
            raise ValueError("invalid design inventory fingerprint")
        inventories = check_pack(arguments.pack, fingerprints) if arguments.pack else None

        architecture = tomllib.loads((ROOT / "docs/specs/architecture/dependencies.toml").read_text())
        owners = {
            name: ROOT / path
            for group in architecture["groups"].values()
            for name, path in group["members"].items()
        }
        claims = trace["coverage"]
        ids = [claim["id"] for claim in claims]
        if not ids or len(set(ids)) != len(ids):
            raise ValueError("expected distinct coverage IDs")
        if any(not re.fullmatch(r"[a-z]+(?:-[a-z]+)*", identifier) for identifier in ids):
            raise ValueError("invalid coverage ID")
        for claim in claims:
            try:
                check_claim(claim, owners, inventories)
            except (KeyError, OSError, ValueError) as error:
                raise ValueError(f"{claim['id']}: {error}") from error
    except (KeyError, OSError, ValueError) as error:
        print(f"requirements trace: {error}", file=sys.stderr)
        return 1

    print(f"Checked {len(claims)} scoped requirements trace entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
