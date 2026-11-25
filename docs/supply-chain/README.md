# Dependency and build evidence

The [Cargo feature matrix](../specs/features/matrix.json) records the supported
build profiles and target triples, the CLI dependency footprint on each target,
and the purpose and feature selection for each direct third-party dependency.
[Cargo.lock](../../Cargo.lock) pins resolved versions and registry source
checksums. The [license and source policy](../../deny.toml) and
[dependency audit policy](../../supply-chain/README.md) govern admission.

## Build and capability scope

| Target | CLI file comparison | CLI copy and recovery | Opt-in workspace features |
| --- | --- | --- | --- |
| Linux x86_64 GNU | Exact comparison of local regular files | Verified single-file copy and recovery | Proof extraction |
| macOS ARM64 | Exact comparison with `--managed-macos` in qualified owner-managed APFS directories | Explicitly unsupported | Proof extraction and experimental managed APFS transfer library |
| Windows x86_64 MSVC | Explicitly unsupported | Explicitly unsupported | Proof extraction |

The minimal, default, and all-stable profiles currently select the same product
capabilities. CI checks those profiles, each applicable opt-in feature, and the
combination of all features applicable to the target. The experimental APFS
runtime requires `exacopy-engine/experimental-apfs-copy` and has a separate macOS test run.
The macOS CLI comparison opt-in is a runtime filesystem contract. The CLI
rejects unavailable operations with explicit unsupported outcomes. See the
[CLI guide](../../crates/clients/cli/README.md) for the operation contracts.

Linux's transfer feature set always includes bounds checking, staging and
read-back verification, integrity framing, authenticated publication intent,
exclusive publication and recovery. The macOS experimental feature enables
the native composition and its transfer policies, including the integrity
and recovery mechanisms.
GUI, networking, VPN, Android, cloud storage, backup repositories, and
specialized document processing have no production feature or dependency.

```sh
python3 tools/feature_matrix.py --target aarch64-apple-darwin
python3 tools/feature_matrix.py --target x86_64-unknown-linux-gnu --graph-only
python3 -B -m unittest discover -s tools -p '*_test.py'
```

Use the native target for compilation. Graph-only mode checks declared features,
dependency feature selections and target-resolved graphs. CI also runs native
tests. The feature matrix directly checks that proof extraction is isolated from
product builds and that the experimental transfer dependencies are absent when
the macOS library is disabled.

## Dependency suitability

The [locked dependency inventory](../specs/dependencies/README.md) records the
production graph for the three supported targets and the review status of
selected direct dependencies. Verify the current graph with
`python3 -B tools/dependency_review/check.py --offline`.

For a dependency addition or upgrade, record the exact lockfile change,
upstream source and maintenance or release evidence, RustSec findings, license
and notice obligations, target and architecture support, transitive footprint,
unsafe and build-script exposure, resource bounds and adversarial input
behavior, applicable tests or proofs, and replacement cost. Keep individual
review records and peer audit attribution under
[`supply-chain/`](../../supply-chain/). Cargo-deny, cargo-audit, cargo-vet,
Gitleaks and Trivy retain separate results in CI. Missing review coverage
continues to block the audit gate.

| Direct dependency | Suitability and review boundary |
| --- | --- |
| `blake3` | Official BLAKE3 implementation. The transfer code streams fixed-size buffers and verifies the stage independently. Review architecture-specific native code and build scripts. Replacement must preserve digest identity or define a versioned migration. |
| `crc32c` | Fast noncryptographic frame corruption detection. Called on bounded frames. Review runtime instruction detection and its software path. An equivalent implementation must preserve CRC32C parameters and format vectors. |
| `ed25519-dalek` and `zeroize` | Upstream signature and key handling primitives. ExaCopy feeds fixed-size public keys and signatures and bounds the signed record first. Review constant-time behavior, zeroization coverage, and transitive cryptographic code. Replacement needs authenticated format compatibility and security review. |
| `minicbor` | Explicit CBOR tags and byte framing with allocation features disabled. Journal readers validate bounds and typed records. Validate codec changes against malformed inputs, persisted fixtures and the journal fuzz target. Replacement must keep the canonical encoding and unknown-version rejection. |
| `getrandom` | macOS-only stage-attempt entropy through the system getentropy backend. Errors prevent private stage creation and preserve the original OS cause. |
| `rustix` and `libc` | Narrow filesystem, process and entropy feature selection with native dependencies gated by target. Review raw-syscall and FFI behavior against each adapter's rights, identity, durability and no-clobber contract. A replacement needs native adapter qualification. |
| `serde` and `serde_json` | CLI wire output uses explicit fields and enum encodings. The derive macro is a build input. Test output structure and exit behavior during migrations. Compare native report output against existing fixtures before changing the encoder. |
| `uuid` | Fixed-size domain identifiers with random generators and serializers disabled. Model properties exercise identity binding. A replacement needs the same stable byte representation. |

`hax-lib` and its proc macro belong to the verification profile. Their version
must match the extractor and the proof toolchain. The initial model review
record reports incomplete peer-audit coverage in the
[foundation evidence](../foundation.md#evidence-and-reproduction).

## Unsigned CLI rebuild evidence

The Linux x86_64 release-evidence job builds `exacopy-cli` twice from one Git
revision. It uses two separate source and target directories, the pinned Rust
release, locked dependencies, the default platform CPU baseline and normalized
source paths. The two builds run offline after a locked dependency fetch.
The runner clears ambient Rust and native compiler flags and compiler wrappers
for the measured builds. Compiler commands containing host-native CPU flags
are refused. The evidence records the runner digest and effective Rust flags.
The gate requires identical executable and SBOM SHA-256 digests.

```sh
python3 tools/sbom_release.py --target x86_64-unknown-linux-gnu --fetch \
  --output target/unsigned-cli-rebuild
```

Use Python 3.12 or newer and a native Rust toolchain. The input is the Git archive
of `HEAD`. Commit changes before collecting revision-specific release evidence.
The output directory must be new. CI retains compiler messages, both
CycloneDX 1.6 inventories and the rebuild record with revision, compiler and
native tool information. The SBOM lists Cargo build inputs, including build
scripts and procedural macros, with their resolved features, declared licenses,
and registry archive checksums. Cargo build messages bind the inventory to the
selected binary. System libraries, link-level package relationships and
distribution packaging require their own inventories.

This gate establishes same-runner reproducibility for the unsigned CLI payload.
Independent machine rebuilds and signed distribution artifacts require
separate evidence. Cargo's graph and build message formats and the SBOM fields
are defined in their respective references. [Cargo dependency graph](https://doc.rust-lang.org/cargo/commands/cargo-tree.html)
[Cargo build messages](https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages)
[CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/)
