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

## Records left open

| Package | Finding or unresolved review boundary |
| --- | --- |
| `hax-lib-macros 0.4.2` | A native refinement fixture accepted a value contrary to its documented debug-check behavior. Selecting the debug-check opt-out instead generated a type error. The current ExaCopy range proof uses no refinement annotation. |
| `find-msvc-tools 0.1.15` | The reviewed COM/BSTR conversion requires a non-null pointer even for an empty slice. Producer documentation did not establish that precondition for every active getter. This is unresolved FFI evidence; no native null return or exploit was reproduced. |
| `toml 1.2.1+spec-1.1.0` | Default guards bound grammar nesting and dotted-key paths separately. A bounded fixture composed a 96-level semantic tree while guards were enabled. Recursive dynamic-value construction/drop and combined depth remain open; no stack exhaustion was reproduced. |
| `toml_parser 1.1.5+spec-1.1.0` | Standard event receivers do not automatically apply the separately available recursion guard. Explicit guarded fixtures passed. The public entry-point and receiver depth contract remains open in this review. |
| `futures-task 0.3.34` | Borrowed-waker pointer reconstruction has an unresolved public `Arc::from_raw` precondition, despite compatibility with the inspected standard-library implementation. Ownership tests passed; they do not settle that contract question. |
| `memchr 2.8.3` | Source/provenance and several native feature tests were inspected, but the whole-version review was unfinished, including optional logging behavior. No audit record was issued. |
| `serde_json 1.0.154` and `zmij 1.0.23` | The additional whole-version review was unfinished. No new audit record was issued. Existing typed CLI serialization tests are a narrower result. |

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
