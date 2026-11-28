"""Validate finding identifiers without logging filenames or matched content.

Resolve path_id against SHA-256 hashes of exact Git tree path bytes at commit;
opening file contents is unnecessary for that lookup.
"""

import json
import re
import sys

MAX_BYTES = 1024 * 1024
RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")
COMMIT = re.compile(r"[a-f0-9]{40}")
PATH_ID = re.compile(r"[a-f0-9]{64}")
FIELDS = {"rule", "path_id", "line", "commit"}


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate metadata field")
    return fields


def locations(data):
    if len(data) > MAX_BYTES:
        raise ValueError("metadata report exceeds its byte limit")
    records = json.loads(data.decode("utf-8"), object_pairs_hook=unique_fields)
    if not isinstance(records, list):
        raise ValueError("expected an array of finding locations")
    for record in records:
        if not isinstance(record, dict) or record.keys() != FIELDS:
            raise ValueError("unexpected finding fields")
        rule, path_id, line, commit = (record[name] for name in ("rule", "path_id", "line", "commit"))
        if (
            not isinstance(rule, str) or not RULE.fullmatch(rule)
            or not isinstance(path_id, str) or not PATH_ID.fullmatch(path_id)
            or type(line) is not int or not 1 <= line <= 2**31 - 1
            or not isinstance(commit, str) or not COMMIT.fullmatch(commit)
        ):
            raise ValueError("unsafe finding location")
    return records


def main():
    try:
        records = locations(sys.stdin.buffer.read(MAX_BYTES + 1))
    except (OSError, ValueError, RecursionError):
        print("Gitleaks metadata report refused", file=sys.stderr)
        return 1
    print(json.dumps(records, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
