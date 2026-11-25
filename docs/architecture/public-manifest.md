# Public single-file manifest profile

Decision MNF-001, 2026-11-25. This work package implements the first portable
manifest codec for R-160/A-160 and bounded admission for R-182/A-182. The
read-only create/verify workflow additionally targets R-007/A-007,
R-016/A-016, R-087/A-087, R-092/A-092, R-154/A-154 and R-161/A-161.
Its safety scope includes INV-001, INV-013, INV-016, INV-019, INV-020 and
INV-032. The codec owns representation, not filesystem authority.

## Supported representation

`exacopy-codec` implements an unsigned public manifest `1.0` with exactly
one regular-file entry, one Unix basename component and one unnamed
BLAKE3-256 stream. Consistency is `live_observed`, `complete` is true for
that selected content scope, `metadata_ref` is null, and continuation pages,
errors and extensions are empty. Signatures, other algorithms, metadata
bundles, multiple streams, directory trees and other path encodings are
outside this initial profile and are refused.

Input is at most 16 KiB of UTF-8 JSON with at most 32 nested containers.
The parser checks nesting before recursive JSON visitors, including values
in unsupported records. The basename is 1–255 raw bytes without NUL, slash,
`.` or `..`; length is at most `2^63-1`. Identifiers use canonical non-nil
UUID text. Digests use lowercase hexadecimal, raw names use canonical padded
standard Base64, and lengths use canonical unsigned decimal strings.
Unknown fields, duplicate supported fields, trailing documents, invalid
primitives and oversized inputs are refused. These are admission limits,
not a claim that other public profiles or filesystems have the same bounds.

The source contract is the architecture pack's manifest JSON schema and
`PUBLIC_RECORD_FIELDS.md` projection. Body keys are numeric 0, 1–7 and 127.
Paths, components and streams use their registered numeric maps. Inline
entry maps retain the schema's exact text keys. CBOR uses definite-length
containers, shortest arguments and RFC 8949 core deterministic encoded-key
order. Display annotations are discarded before hashing and never select
filesystem paths. Required logical fields are retained without Unicode
normalization.

## Digest decision

The pack requires a manifest envelope digest but explicitly registers its
manifest domain under the signature message. MNF-001 fixes the unsigned
envelope rule as:

```text
envelope_digest = BLAKE3("ExaCopy/manifest/v1" || NUL || canonical_body)
stream_digest   = BLAKE3(logical_file_bytes)
```

The envelope body excludes its digest and any signature. The first rule
uses the existing manifest message domain; it introduces no signature or
authentication claim. The ordinary unprefixed stream digest remains
interoperable with independent BLAKE3 tools. A body-digest mismatch is an
integrity error, distinct from malformed input or an unsupported profile.

## Read-only workflow boundary

The codec alone does not read or verify a filesystem object. The workflow
binds `PATH` and the separately selected baseline file through read-only
held roots. The baseline's logical root UUID is an opaque label mapped by
the caller to the selected parent; it grants no access. The raw basename
must match. Paths and display hints inside the manifest never initiate
filesystem lookup.

`manifest create` measures a fresh baseline. It cannot establish integrity
against an unknown earlier state. `verify` compares current content with a
caller-selected trusted baseline. An unsigned envelope does not authenticate
who created the baseline or when. Metadata is explicitly omitted from the
verification claim. Live pre/post observations and EOF/name checks detect
their supported change conditions; they do not create a snapshot.

The operation policy compares the expected length/digest only after the
final current-file observation succeeds. A changed observation takes
precedence over a byte mismatch. The caller also retains and revalidates
the baseline through the target observation. Source content and namespace
receive no application mutation capability. Ordinary reads may update atime.

The codec and Linux CLI creation/verification commands are implemented.
Native ARM64 Linux/ext4 validation exercised the integrated workflow,
including raw names, unchanged source/baseline bytes and inode identities,
independent golden input, stale name replacement, and an actual output
space error. macOS and Windows CLI routes refuse this operation explicitly. Private Linux copy receipts remain journal-bound
artifacts and are not reinterpreted as portable manifests.

## Evidence and remaining assurance

The [crate-local vectors](../../crates/core/codec/verification/manifest/README.md)
come from an independent Python projection and encoder plus the pinned
portable C BLAKE3 implementation. They cover empty content, non-UTF-8 raw
names and the signed-length boundary. The maximum-length stream digest is
synthetic; no giant file was read. Rust compares exact canonical bytes and
envelope digests, and standalone cross-language decoders checked the
fixtures. Display annotations leave the canonical bytes unchanged.

Seventeen ordinary codec tests passed after adding structural depth and
diagnostic-redaction cases. The measured codec coverage was 379/387 lines
(97.93%) and 77/78 branch outcomes (98.72%), without product-source
exclusions. Six deliberately changed source predicates were detected by
their tests; a complete mutation score remains unmeasured.
The bounded AddressSanitizer campaign completed 250,000 inputs at seed
18723 with a maximum input length of 16,385 bytes and no failure artifact.
Raw initial and depth-limited campaign records are retained separately at
`/private/tmp/exacopy-public-manifest.OdSXc5/fuzz-evidence-initial` and
`/private/tmp/exacopy-public-manifest.OdSXc5/fuzz-evidence-final-depth`.
These are executed fixture/parser results. They do not establish universal
parser refinement, filesystem qualification or historical authenticity.
The root verification ledger records its actual Rust gate; the separate
[fuzz runner](../../crates/core/codec/verification/manifest/check-fuzz.sh)
records source, lock, sanitizer, seed and budget information for each run.

The native CLI integration probe is retained at
[`manifest_probe.py`](../../crates/clients/cli/tests/manifest_probe.py). Run it
on Linux with the CLI binary and the codec vector directory as its two
arguments. The native pre-commit snapshot, raw logs and JUnit are retained
at `/private/tmp/exacopy-manifest-native.0S53Xk`. Its 546 passing tests and
six skipped crash-child entrypoints precede the six additional portable
codec admission tests.
