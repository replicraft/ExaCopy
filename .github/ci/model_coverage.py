"""Validate the exact core and model coverage inventory and integer thresholds."""

import json
import math
from pathlib import Path
import sys

WORKSPACE = Path(__file__).resolve().parents[2]
EXPORT_TYPE = "llvm.coverage.json.export"
EXPORT_VERSION = "3.1.0"
CARGO_LLVM_COV_VERSION = "0.9.1"
MINIMUM = {"lines": 95, "branches": 90}
SOURCES = frozenset((
    "crates/foundation/exacopy-core/src/identity.rs",
    "crates/foundation/exacopy-model/src/binding.rs",
    "crates/foundation/exacopy-model/src/protected_replace.rs",
    "crates/foundation/exacopy-model/src/protected_replace/effect.rs",
    "crates/foundation/exacopy-model/src/protected_replace/evidence.rs",
    "crates/foundation/exacopy-model/src/protected_replace/selection.rs",
    "crates/foundation/exacopy-model/src/range.rs",
    "crates/foundation/exacopy-model/src/retained_prefix.rs",
    "crates/foundation/exacopy-model/src/retained_prefix/budget.rs",
    "crates/foundation/exacopy-model/src/sync.rs",
    "crates/foundation/exacopy-model/src/sync_genesis.rs",
    "crates/foundation/exacopy-model/src/transaction.rs",
    "crates/foundation/exacopy-model/src/witnessed_publication.rs",
    "crates/foundation/exacopy-model/src/witnessed_publication/state.rs",
))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate coverage JSON field {key!r}")
        result[key] = value
    return result


def reject_constant(token):
    raise ValueError(f"invalid coverage JSON number {token}")


def parse_report(data):
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)


def field(record, name, kind):
    if isinstance(record, dict) and type(record.get(name)) is kind:
        return record[name]
    raise ValueError(f"invalid coverage field {name!r}, expected {kind.__name__}")


def counts(summary, dimension):
    item = field(summary, dimension, dict)
    count = field(item, "count", int)
    covered = field(item, "covered", int)
    if not 0 <= covered <= count:
        raise ValueError(f"inconsistent coverage counts for {dimension}")
    if dimension == "branches" or "notcovered" in item:
        if field(item, "notcovered", int) != count - covered:
            raise ValueError(f"inconsistent uncovered count for {dimension}")
    percent = item.get("percent")
    calculated = 100 * covered / count if count else 0
    if (type(percent) not in (float, int) or not 0 <= percent <= 100
            or not math.isclose(percent, calculated, abs_tol=1e-8)):
        raise ValueError(f"inconsistent coverage percentage for {dimension}")
    return count, covered


def validate(report, workspace):
    """Check the LLVM export envelope and exact workspace-rooted source summaries."""
    if (field(report, "type", str) != EXPORT_TYPE
            or field(report, "version", str) != EXPORT_VERSION):
        raise ValueError("wrong LLVM coverage export type or version")
    tool = field(report, "cargo_llvm_cov", dict)
    if field(tool, "version", str) != CARGO_LLVM_COV_VERSION:
        raise ValueError("wrong cargo-llvm-cov version")
    if field(tool, "manifest_path", str) != str(workspace / "Cargo.toml"):
        raise ValueError("coverage export belongs to a different workspace")
    datasets = field(report, "data", list)
    if len(datasets) != 1:
        raise ValueError("expected one LLVM coverage data set")
    dataset = datasets[0]
    if isinstance(dataset, dict) and "functions" in dataset:
        functions = field(dataset, "functions", list)
        if not functions or any(not isinstance(function, dict) for function in functions):
            raise ValueError("invalid functions in full LLVM coverage export")

    paths = {str(workspace / name): name for name in SOURCES}
    seen = set()
    sums = {dimension: [0, 0] for dimension in MINIMUM}
    for item in field(dataset, "files", list):
        filename = field(item, "filename", str)
        if filename not in paths:
            raise ValueError(f"unexpected coverage source {filename!r}")
        if filename in seen:
            raise ValueError(f"duplicate coverage source {paths[filename]}")
        seen.add(filename)
        # Location arrays are diagnostic. The reconciled summaries own the gate.
        for detail, row_kind in (("branches", list), ("segments", list), ("expansions", dict)):
            if detail in item and any(type(row) is not row_kind for row in field(item, detail, list)):
                raise ValueError(f"invalid coverage location array {detail!r}")
        if "mcdc_records" in item:
            field(item, "mcdc_records", list)
        summary = field(item, "summary", dict)
        for dimension in MINIMUM:
            count, covered = counts(summary, dimension)
            if dimension == "lines" and count == 0:
                raise ValueError(f"zero line count for {paths[filename]}")
            sums[dimension][0] += count
            sums[dimension][1] += covered
    if missing := paths.keys() - seen:
        raise ValueError(f"missing coverage sources: {', '.join(sorted(paths[name] for name in missing))}")

    totals = {}
    summary = field(dataset, "totals", dict)
    for dimension in MINIMUM:
        count, covered = counts(summary, dimension)
        if count == 0:
            raise ValueError(f"zero total coverage count for {dimension}")
        if [count, covered] != sums[dimension]:
            raise ValueError(f"coverage totals disagree with file summaries for {dimension}")
        totals[dimension] = (count, covered)
    return totals


def shortfalls(totals):
    return [
        dimension for dimension, minimum in MINIMUM.items()
        if totals[dimension][1] * 100 < totals[dimension][0] * minimum
    ]


def main(arguments):
    if len(arguments) != 1:
        print("usage: model_coverage.py COVERAGE_JSON", file=sys.stderr)
        return 2
    try:
        report = parse_report(Path(arguments[0]).read_text(encoding="utf-8"))
        totals = validate(report, WORKSPACE)
    except (OSError, ValueError, RecursionError) as error:
        print(f"invalid model coverage: {error}", file=sys.stderr)
        return 1

    below = shortfalls(totals)
    for dimension, (count, covered) in totals.items():
        outcome = "fail" if dimension in below else "pass"
        percent = 100 * covered / count
        print(f"{dimension}: {covered}/{count} ({percent:.4f}%, minimum {MINIMUM[dimension]}%, {outcome})")
    return int(bool(below))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
