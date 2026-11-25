# Unsigned public Plan JSON

The `exacopy-plan::PublicPlan` JSON envelope presents the canonical
[public Plan body](public-plan-body.md). Parsing recomputes the canonical
body digest and compares it with the declared digest. Serialization emits
the same semantic body with normalized UTC timestamps. This is a codec,
not approval verification, page loading, root authorization or execution.

Every required field must appear. Typed records must be JSON objects;
missing, duplicate, unknown and trailing fields are rejected. Any attached
`approval` field, including null, is refused. `approval_required` remains
an intent field and grants no authority. Extensions preserve accepted
semantics in canonical CBOR; duplicate keys are rejected even when their
JSON escape spellings differ.

The wire limits are 8 MiB of JSON and 33 container levels including the
envelope, with the body's separate 1 MiB and 32-container caps. Collection
limits are enforced during parsing. These are representation bounds, not
peak-memory claims. Extensions admit null, booleans, text, arrays, unique
text-keyed maps and exact integers from -2^64 through 2^64-1. They reject
floating and exponential spellings. The resource field `io_inflight_max`
accepts exactly integer-valued JSON numbers from 1 through 64, including
`1.0` and `1e0`, without floating-point conversion; output uses integers.

Timestamps require an ASCII four-digit date, T/t separator, seconds,
optional one-to-nine fractional digits and Z/z or a numeric offset.
Chrono 0.4.45 with defaults disabled and only `alloc` enabled checks calendar
values and normalizes offsets. Leap seconds, excess precision and UTC
normalization outside years 0000–9999 are refused. No clock or timezone
lookup occurs. This selected dependency profile does not close Chrono's
whole-version supply-chain gate: independent review retained unresolved
mobile timezone parsing and optional archived-value invariant questions.
Those features are disabled; no whole-version audit was awarded.

[Independent vectors](../../crates/formats/exacopy-plan/verification/plan_json/README.md)
use Python mappings and the pinned portable C BLAKE3 implementation. Tests
cover malformed structures, exact integer boundaries, timestamps and digest
binding. Fifty native codec tests passed for the final parser candidate;
independent probes exercised exact maximum sizes, nesting and escaped keys.
The corrected parser completed 250,000 AddressSanitizer inputs without
failure artifacts. Raw logs, earlier failures and source hashes remain in
`/private/tmp/exacopy-public-plan-json.Q132oZ` and the independent review in
`/private/tmp/exacopy-plan-json-review.TTyOnMCL`.

P-039 is a scoped Rust parser-admission gate. These checks establish no
native filesystem, process-crash, power-loss or signed-approval result.
The [execution bridge](public-plan-bridge.md) records the remaining binding
between public plans, approved bytes and recoverable job state.
