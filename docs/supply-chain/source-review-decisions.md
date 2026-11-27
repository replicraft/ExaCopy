# Source review decisions, 2026-11-25

These are automated Codex source reviews of exact locked archives, not
independent human audits or platform qualification. Accepted records are in
[`supply-chain/audits.toml`](../../supply-chain/audits.toml), including their
archive checksums, source provenance, assumptions and executed test scope.
Cargo Vet still decides whether the complete dependency graph has its
required criteria. An accepted package does not close an open dependency.

## Additional accepted records

| Package | Scope and limits |
| --- | --- |
| `cc 1.11.2` | Command construction, compiler discovery, output paths, jobserver and optional compiler paths under trusted toolchain/build inputs. Native compiler fixtures, 48 unit tests and 33 doctests passed. Linux and Windows target checks compiled; native Windows discovery remains unexecuted. |
| `hax-lib 0.4.2` | Exact Rust/build-script source, placeholder and backend-cfg paths. The normal proof-extraction feature and focused stable/nightly fixtures compiled. Native proposition placeholders are not logical decision procedures; the native implication stub and upstream Lean model have different semantics. This record does not establish backend proof soundness. |
| `hax-lib-macros-types 0.4.2` | Typed metadata, escaped token emission, fresh linkage labels and optional schemas. Focused serialization, token and pinned-nightly fixtures passed. Labels are not authentication. Backend quotation interpretation remains a separate boundary. |
| `anstyle 1.0.14` | Fixed-buffer UTF-8 formatting and caller-owned output. Native checks covered every byte-sized color component; the upstream suite was blocked by an uncached test dependency. |
| `clap 4.6.10`, `clap_builder 4.6.10`, `clap_lex 1.1.2` | Exact facade, parser, feature and native-string paths. Fallible parsing, help, unknown flags and non-UTF-8 arguments passed native ARM64 checks. Environment values and diagnostics remain application policy; optional derive code is a separate package. |
| `base64 0.23.1` | Scalar, streaming, unsafe SIMD bounds and CPU dispatch reviewed. Native ARM64 scalar/NEON differential and output-canary checks passed. Translated x86-64 exercised scalar fallback; AVX2 was source-reviewed without native execution. ExaCopy selects scalar alloc-only operation. |

The five CLI/codec records removed exactly five missing entries from the
frozen Cargo Vet report at `98dacb7`, reducing 48 to 43. The remaining
workspace gate still fails. Exact source comparisons, probes, original
test-resolution failure and before/after reports are retained at
`/private/tmp/exacopy-cli-codec-vet.OpfvI4/`.

Subsequent exact-version reviews accepted `indexmap 2.14.2` for
`safe-to-deploy`, and `rand 0.10.4`, `rand_xorshift 0.5.0` and
`regex-syntax 0.8.12` for controlled `safe-to-run`. IndexMap passed 240
native tests/doctests and 15 Miri tests. Regex passed 149 default and
146 no-default unit tests and 48 doctests. RNG probes covered optional
thread-local reseeding, bounded serialized state and nightly SIMD;
untrusted sampler state and a generator that cannot progress remain
outside those controlled-run assumptions. Their full upstream suites
retained offline dependency-resolution limits. These four records reduce
the remaining missing entries from 43 to 39, without changing criteria.
Evidence is retained in `/private/tmp/exacopy-indexmap-review.BHRJW07M`,
`/private/tmp/exacopy-rand-source-review.9cfLEYzW` and
`/private/tmp/exacopy-proptest-audit.2hCiYI`.

The 2026-11-27 whole-package source review accepted `aead 0.6.1` and
`inout 0.2.6`. Independent review checked all archived members against
the locked checksums and reviewed optional features. These records cover
the adapter and buffer contracts, without certifying concrete ciphers,
RNGs, timing, or platform execution. No compilation or tests ran for these
two reviews. The exact frozen Cargo Vet replay removed only their two
missing `safe-to-deploy` entries, reducing 178 to 176. The gate still fails.
Reports, original findings and both replay results are retained under
`target/agent-evidence/dependency-audits-next/`.

The next independent source adjudication accepted `hybrid-array 0.4.15`
and `universal-hash 0.5.1` and `0.6.1`. The latter retain an undocumented
zero-width panic: trusted backend implementations select a positive
supported block width at compile time, and message input cannot select it.
The prior holds and this disposition remain recorded. These are source
reviews, with no new compiler, Miri, runtime or timing result. A frozen
replay removed exactly those three missing entries, reducing 176 to 173;
the gate still fails. Evidence is retained under
`target/agent-evidence/dependency-audits-round2/`.

Six further paired source reviews accepted `hkdf 0.13.0`,
`jiff-static 1.0.3`, `shake 0.1.0`, `wasm-bindgen-macro 0.2.130`,
`windows-numerics 0.3.1` and `x25519-dalek 2.0.1`. The HKDF and SHAKE
records retain trusted compile-time backend width and resource assumptions;
runtime message input cannot select those types. Dependencies, cryptographic
correctness, timing and native execution remain separate review boundaries.
Both complete member inventories matched the six locked archives. Actual
frozen Cargo Vet replay removed exactly those six missing entries, reducing
173 to 167, with the lockfile, criteria and imports unchanged. Both replay
runs still failed the workspace gate. Evidence and the original findings
remain under `target/agent-evidence/audit-six-integration/`.

The paired source review of `zmij 1.0.23` accepted an exact-version
`safe-to-deploy` record with explicit built-in discretion. Both readers
verified all 17 locked archive members and reviewed buffer, table, SIMD and
UTF-8 invariants. A big-endian AArch64 NEON numeric-order defect and a private
test-helper bounds defect remain recorded. This is no numerical round-trip or
native qualification. No dependency code ran during review. The hosted
`cargo vet --locked` replay at `adba747` removed exactly the `zmij 1.0.23`
gap, reducing 166 to 165 without changing any other missing record. The gate
still failed; 164 `safe-to-deploy` and one `safe-to-run` records remain open.
[Exact dependency-policy job](https://github.com/replicraft/ExaCopy/actions/runs/46037037379/job/140634944275).
The local review and inventories are retained under
`target/agent-evidence/dependency-source-continuation/zmij/`.

The paired source and artifact review of `windows_i686_msvc 0.52.6`
accepted an exact-version `safe-to-deploy` record. Both readers matched all
eight published members to the locked archive and inspected its i386 COFF
import library. Both indexes agree across 41,845 keys, and the packaged
objects have no executable or linker-directive sections. The record assumes
trusted Cargo build paths, linker and deployment module lookup. Imported
module basenames do not authenticate resolved modules. Native linking,
external ABI behavior and independent generation remain unverified. No package
code ran. The hosted `ab8319a` replay removed exactly this package's gap,
reducing 165 to 164: 163 `safe-to-deploy` and one `safe-to-run` records remain.
The gate still fails; its other rows and dependency-policy outputs are unchanged.
[Exact dependency-policy job](https://github.com/replicraft/ExaCopy/actions/runs/46048291349/job/140672939545).
The record, two independent reviews and complete member inventories remain under
`target/agent-evidence/dependency-source-next/`.

The paired review of `windows_i686_gnu 0.52.6` accepted a whole-version
`safe-to-deploy` record. Both readers verified all eight locked archive members
and accounted for 21,293 i386 COFF objects and 41,844 index keys. Unlike the
MSVC archive, it contains executable code: 20,551 fixed eight-byte import
thunks whose relocations select their own import-address slots. The complete
module and export routing matched the independently inspected MSVC encoding.
Trusted build inputs, linker and deployment module lookup remain assumptions;
external ABI behavior, native linking and independent regeneration are
unverified. No package code ran. At `82d8d74`, hosted Cargo Vet removed only
this package's missing audit row, reducing the report from 164 to 163 gaps.
The gate still fails; all other rows remain unchanged and in the same order.
[Exact dependency-policy job](https://github.com/replicraft/ExaCopy/actions/runs/46067206611/job/140735317015).
Both source reviews, complete member inventories and artifact readers remain under
`target/agent-evidence/dependency-source-next-4831/`.

The paired whole-package review of `windows_i686_gnullvm 0.52.6` accepted
a `safe-to-deploy` record for its exact locked archive. Both readers accounted
for all eight members, 20,551 short import descriptors, 1,113 nonexecutable
COFF objects and all 42,215 index entries. Decorated i386 routes match the
reviewed MSVC encoding; the linker supplies any executable import thunks.
Trusted build inputs, native linking and deployment-controlled module lookup
remain assumptions. Native execution and upstream regeneration remain
unqualified. Cargo Vet replay is pending; the last verified report has 163
gaps. The reviews and complete inventories remain under
`target/agent-evidence/dependency-gnullvm-next/`.

## Records left open

| Package | Finding or unresolved review boundary |
| --- | --- |
| `hax-lib-macros 0.4.2` | A native refinement fixture accepted a value contrary to its documented debug-check behavior. Selecting the debug-check opt-out instead generated a type error. The current ExaCopy range proof uses no refinement annotation. |
| `find-msvc-tools 0.1.15` | The reviewed COM/BSTR conversion requires a non-null pointer even for an empty slice. Producer documentation did not establish that precondition for every active getter. This is unresolved FFI evidence; no native null return or exploit was reproduced. |
| `toml 1.2.1+spec-1.1.0` | Default guards bound grammar nesting and dotted-key paths separately. A bounded fixture composed a 96-level semantic tree while guards were enabled. Recursive dynamic-value construction/drop and combined depth remain open; no stack exhaustion was reproduced. |
| `toml_parser 1.1.5+spec-1.1.0` | Standard event receivers do not automatically apply the separately available recursion guard. Explicit guarded fixtures passed. The public entry-point and receiver depth contract remains open in this review. |
| `futures-task 0.3.34` | Borrowed-waker pointer reconstruction has an unresolved public `Arc::from_raw` precondition, despite compatibility with the inspected standard-library implementation. Ownership tests passed; they do not settle that contract question. |
| `memchr 2.8.3` | Source/provenance and several native feature tests were inspected, but the whole-version review was unfinished, including optional logging behavior. No audit record was issued. |
| `serde_json 1.0.154` | Two source reviews verified all 90 archive members and withheld the whole-version record: the public safe reader does not enforce the invariant needed by its unchecked UTF-8 conversion under std or alloc. Optional raw-value grammar validity is a separate concern. No reproduction ran, and no direct low-level reader use was identified in ExaCopy's bounded typed input paths. |
| `proptest 1.12.0` | Source review found that a nested runner can inherit and open the outer runner's internal replay channel without selecting its own fork. The current std-only feature selection excludes that path; 13 model integration tests passed. Whole-version `safe-to-run` remains withheld pending disposition. |
| `slab 0.4.12` | Optional Serde decoding allocates holes up to the largest map key before returning a value for caller validation. Native and Miri ownership tests passed, but the whole-version `safe-to-deploy` record remains withheld. Current locked selection uses std without Serde. Evidence: `/private/tmp/exacopy-slab-vet.CXdsE3`. |
| `aead 0.5.2` | Optional STREAM advances its nonce position only after successful delegation; a fallible postfix tag append can fail after message mutation. The failed-call disposition remains unresolved. The inspected ExaCopy feature selection excludes STREAM. |
| `inout 0.1.4` | Optional padding retains a mutable tail reference while reconstructing a whole-output view. The aliasing concern is a source inference; this review did not reproduce it with Miri. The inspected ExaCopy selection excludes padding for this version. |
| `hash32 0.3.1` | Murmur3 forms references to a not-yet-fully-initialized four-byte tail. The inspected experimental WireGuard stack has no named Murmur3 or hashed-map use. No runtime activation or reproduction is claimed. |
| `cargo-platform 0.3.3` | Runtime cfg parsing permits unbounded nesting, and identifier equality differs from derived ordering. The xtask caller's depth bound was not established. |
| `block-padding 0.4.2` | Raw unpadding can panic on empty or oversized borrowed slices despite its fallible malformed-input API. The separately inspected fixed-width typed AES path rejects empty block lists. |
| `const-oid 0.10.3` | Generic capacity permits an internally valid length to narrow to `u8`; runtime text parsing also permits unbounded recursive prefix zeros. The default capacity does not settle the whole-version review. |
| `serdect 0.4.3` | Fixed-size text decoding can accept a short hex value after initializing the remaining output to zero; binary decoding enforces the exact length. The recorded application feature graph excludes this path. |
| `ed25519 3.0.0` | PKCS#8 import normalizes a present, non-octet-aligned public-key BIT STRING to absence. Optional Serde handling also inherits the short fixed-array text issue. These format findings do not assess the signature algorithm. |
| `cmov 0.5.4` | The 32-bit x86 backend uses conditional-move instructions without establishing their availability on the advertised i586 baseline. The recorded x86-64 and AArch64 profiles have the respective instructions. No timing result is claimed. |
| `log 0.4.35` | The no-pointer-atomics unsafe setter contract does not establish exclusion of concurrent readers. Optional Serde enum decoding also narrows a `u64` identifier before validation on narrow targets. The recorded application graph uses pointer atomics without that Serde branch. |

Previously withheld records, including `bitflags`, `minicbor`, `zeroize`,
`getrandom`, `cpufeatures`, `ed25519-dalek` and Syn 2, retain their own review
and qualification gaps. This table does not replace the locked Cargo Vet
report or claim that every remaining package has been reviewed.

Raw fixture and trial-store logs remain in the local evidence directories
`/private/tmp/exacopy-cc-msvc-audit.OvMmGOsL`,
`/private/tmp/exacopy-hax-vet.Z9fJ98`,
`/private/tmp/exacopy-toml-closure.5zfHii`,
`/private/tmp/exacopy-vet-closure.MkS9J3`,
`/private/tmp/exacopy-memchr-vet.N7nR3I`. Local temporary artifacts are not
published or durable release attestations.

## Unselected transport candidate

A source-only review of the BoringTun candidate using ChaCha20-Poly1305
0.11.0 found a panic at the public AEAD payload limit. At the initial
payload counter position, the AEAD length guard rounds down while the
stream wrapper requires enough blocks for the partial tail. The
panicking stream method can then turn a length refusal into a panic.
BoringTun's cookie adapter uses a fixed 16-byte payload outside that
boundary. The candidate remains unselected and supplies no new Cargo Vet
record or hosted vector result.
This is a source inference from the published
[AEAD implementation](https://docs.rs/crate/chacha20poly1305/0.11.0/source/src/cipher.rs)
and [stream wrapper](https://docs.rs/crate/cipher/0.5.2/source/src/stream/wrapper.rs),
without a runtime reproduction or a demonstrated WireGuard exposure.
