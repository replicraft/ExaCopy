#!/usr/bin/env python3
"""Admit and build the one-shot unsigned preview candidate on the real main run."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import release_candidate
import testing_remote_asset as packaging
import remote_commissioning_wireguard_provider_b as provider_b

REQUEST = ".github/ci/remote-preview-candidate.json"
PLAN_SCHEMA = "exacopy-main-preview-plan-v1"
REQUEST_FIELDS = {
    "schema": "exacopy-main-preview-request-v1",
    "intended_tag": packaging.PREVIEW_TAG,
    "workspace_version": packaging.PREVIEW_BASE,
    "target": packaging.TARGET,
    "feature": packaging.ROUTE_FEATURE,
}
MAX_REQUEST = 2048
MAX_PLAN = 16 * 1024


def strict_json(data, maximum):
    if not 0 < len(data) <= maximum:
        raise ValueError("preview evidence exceeds its input bound")
    result = json.loads(data, object_pairs_hook=packaging.native.closed_object)
    if not isinstance(result, dict):
        raise ValueError("preview evidence must contain one JSON object")
    return result


def request_object(data):
    record = strict_json(data, MAX_REQUEST)
    if record.keys() != (REQUEST_FIELDS.keys() | {"nonce"}) or any(
        record[key] != value for key, value in REQUEST_FIELDS.items()
    ) or not isinstance(record["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", record["nonce"]):
        raise ValueError("invalid closed preview candidate request")
    return record


def read_bounded(path, maximum):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("preview evidence must be a regular file")
        return stream.read(maximum + 1)


def plan():
    # The unchanged provider admission binds the genuine main workflow and ref.
    provider_b.hosted_scope()
    run = provider_b.dispatch_run()
    source = packaging.native.source_identity(release_candidate.ROOT)
    revision = source["revision"]
    if revision != os.environ["GITHUB_SHA"]:
        raise ValueError("preview controller and clean source differ")
    git = release_candidate.git
    if git("diff-tree", "--no-commit-id", "--name-only", "-r", f"{revision}^1", revision, "--", REQUEST) == "":
        return {"schema": PLAN_SCHEMA, "status": "not-requested"}
    if run["attempt"] != "1":
        raise ValueError("a selected preview request requires the first hosted run attempt")
    request_path = release_candidate.ROOT / REQUEST
    current = git("ls-tree", revision, "--", REQUEST).split()
    if len(current) != 4 or current[:2] != ["100644", "blob"]:
        raise ValueError("selected request must be a tracked regular file")
    parent = git("ls-tree", f"{revision}^1", "--", REQUEST).split()
    if parent[2:3] == current[2:3]:
        raise ValueError("selected request must change the committed policy contents")
    raw = read_bounded(request_path, MAX_REQUEST)
    request = request_object(raw)
    git_header = f"blob {len(raw)}\0".encode("ascii")
    if hashlib.sha1(git_header + raw, usedforsecurity=False).hexdigest() != current[2]:
        raise ValueError("selected request differs from the committed bytes")
    release_candidate.check_workspace_version(request["workspace_version"])
    return {
        "schema": PLAN_SCHEMA,
        "status": "requested",
        "request": request,
        "request_sha256": hashlib.sha256(raw).hexdigest(),
        "source": source,
        "workflow": {
            "ref": os.environ["GITHUB_WORKFLOW_REF"], "sha": revision, "run_id": run["run_id"], "run_attempt": run["attempt"],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    select = commands.add_parser("plan")
    select.add_argument("--output", type=Path, required=True)
    build = commands.add_parser("build")
    build.add_argument("--plan", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    try:
        selected = plan()
        if args.command == "plan":
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(selected, stream, sort_keys=True)
                stream.write("\n")
            return
        incoming = strict_json(read_bounded(args.plan, MAX_PLAN), MAX_PLAN)
        if selected["status"] != "requested" or selected != incoming:
            raise ValueError("build requires an exact selected main preview plan")
        if os.path.lexists(args.output) or os.path.lexists(args.evidence):
            raise ValueError("expected fresh candidate output and evidence paths")
        release_candidate.check_toolchain(packaging.TARGET)
        packaging.build(
            args.output, args.evidence, packaging.PREVIEW_BASE, packaging.PREVIEW_TAG,
            selected["source"]["revision"], candidate=selected,
        )
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, provider_b.Blocked,
            packaging.native.CleanupUnconfirmed) as error:
        if args.command == "plan" and not os.path.lexists(args.output):
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(json.dumps({"schema": PLAN_SCHEMA, "status": "invalid"}, sort_keys=True) + "\n")
        parser.exit(1, f"main preview candidate: {error}\n")


if __name__ == "__main__":
    main()
