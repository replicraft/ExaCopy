# Engineering standards

ExaCopy adopts the complete applicable requirements of EES-1 and EVS-1
from the local ExaCopy Architecture Pack baseline 2.1, dated 2026-11-25.
The following fingerprints identify that adoption. The pack remains under
`docs/temp/exacopy-architecture-pack/` on workstations that have it.
Use the exact texts for work package review. Repository checks run on
the tracked workspace and its owned proof artifacts.

| Adopted standard | Path within the pack | SHA-256 |
| --- | --- | --- |
| EES-1, including the 2026-11-25 amendment | `shared/ENGINEERING.md` | `afd26ce4121030046bfd2be0dc3d0ced9094ac822fb6b9ecc840879645f9c634` |
| EVS-1, including the engineering amendment alignment | `shared/VERIFICATION.md` | `47c9b080e93e26d480a86f3f443089a1853ef8e160128c37456fff2f44b8dc92` |

The pack describes its standards as reconstructions. The reconciliation
below uses subsequently located canonical dmgez files and identifies
their exact Git objects. Where the reconstructed pack describes different contribution licensing,
the repository's first-party Apache-2.0 policy controls. The dmgez
EVS-1 document is titled “proposed”.
ExaCopy's EVS-1 remains mandatory and retains its stronger applicable
requirements.

## Source revisions reviewed

The document paths in this table are relative to each upstream repository.
They identify the committed inputs of the reconciliation. Local Git
objects can be reproduced with `git -C <checkout> show <commit>:<path>`.

| Repository and revision | Documents | Applicable shared conventions and project scope |
| --- | --- | --- |
| pomologie/dmgez `9b5aec755fa545909d33f56f141cf0bb2d638baa` | `docs/architecture/ECOSYSTEM_ENGINEERING.md` (EES-1 revision 3, blob `96789e2724fa26b7588832ac3c13823d5273242e`), `docs/architecture/ECOSYSTEM_VERIFICATION.md` (EVS-1 proposed, blob `6f155578646da4d867d9c93ff4346f3bc41ced1a`) | Adopt the applicable repository, dependency, verification and evidence conventions. The three-checkout coordination and bare-metal gates are specific to integration of dmgez and the independent HFS+/APFS engines. Native image-building, mounting, notarization and kernel-driver evidence apply to those capabilities. |
| replicraft/TableCraft `17d8389d136259d8e9750155f22c7c3392168061` | `AGENTS.md`, `docs/development/DEVELOPMENT.md`, `docs/COMPATIBILITY.md` | Select real ownership boundaries, use declarative roots and explicit exports, qualify each supported profile with retained independent artifacts, and keep private plans local. Access profiles, native Windows oracles and the repository's optimized local Cargo policy apply to TableCraft. |
| replicraft/vba-rs `95425ac226c0f73bf3fd1ec97539e26e351162e7` | `CONTRIBUTING.md`, `SECURITY.md`, `docs/architecture/overview.md` | Compose hosting at the application boundary, keep tooling out of production, use categorized dependency inheritance and provenance-bearing conformance fixtures, and report vulnerabilities privately. VBA language/host contracts and contribution scope apply to vba-rs. |
| PixelSoftwareStudios/EarthCraft `bad15e24e13425dd216397ae432152275d71ffd6` | `AGENTS.md`, `CONTRIBUTING.md` | Keep mechanical moves focused and distinguish headless development checks from desktop and target qualification. Its floating action tags, GUI dependencies and compiler version are repository-specific. ExaCopy pins executable CI inputs to reviewed immutable revisions under EVS-1. |
| PixelSoftwareStudios/Relay `79dcdb650c0b59a2553da2e751f65af70b4ed381` | `rustfmt.toml`, `.github/workflows/ci.yml`, `docs/architecture.md` | Group by domain, keep tooling/configuration with its owner, use pinned toolchains, locked graph checks and separate headless, desktop, native and special toolchain lanes. Relay's Android packaging, protocol, runtimes and test runner exclusions apply to Relay. |
| Dockhand | Canonical source unavailable | The pinned dmgez architecture and roadmap identify Dockhand as a consumer. Its own authoritative checkout or standard revision was unavailable, so exact Dockhand alignment remains open. |

## Applicability and ExaCopy decisions

- Use [AGENTS.md](../../AGENTS.md) for repository execution rules and
  [ARCHITECTURE.md](../../ARCHITECTURE.md) for effect ownership. EES-1 calls
  for typed errors, identifiers and units, checked limits, bounded
  concurrency with owned cancellation, explicit durability and authority,
  and narrow reviewed unsafe boundaries. Preserve context while redacting
  sensitive data. Keep source layout and Cargo policy enforced by the
  tracked checker and human review of actual call graphs.
- Prefer named file modules with explicit imports and exports. Existing
  declarative `mod.rs` is permitted under the adopted EES-1. The ExaCopy
  workspace uses Rust 1.100.0, the 500-physical-line ceiling and hard
  tabs with four-column stops. Existing generated/vendored exclusions
  require documented ownership. The current application crate locations
  are recorded by the dependency matrix. ExaCopy's model remains
  effect-free. The userspace adapter and workflow code uses `std` where
  appropriate. A separately maintained kernel-targeted dependency keeps
  its own bare-metal and release contract.
- Independently owned reusable libraries require separate, reproducible
  verification and releases. Integration records pin repository, commit,
  dirty status, version, checksum, target, features and interface or
  assumption changes. Test the dependency and actual consumer graph
  before activation. Keep checkout-specific paths local. Resolve any
  differing dependency licenses through the dependency review policy.
  ExaCopy contributions use Apache-2.0.
- Use [contract versioning](../architecture/contract-versioning.md) for
  format admission, migrations and recovery. Use the
  [behavioral inventory](../../specs/compatibility/) for reference fixtures,
  intentionally preserved safety differences and independent oracles.
- Review shared contract, lockfile, unsafe and authority changes serially.
  Use disjoint ownership for concurrent work. Integrate small atomic
  commits with their tests and affected documentation. Review actual
  staged paths, preserve independent repository history and user changes,
  and obtain explicit authorization before pushing.
- When an upstream standard changes, record its immutable revision and map
  affected obligations. Review deviations against the relevant evidence and
  document approval, scope and rationale. Use a scoped decision record for
  platform, toolchain or qualification exceptions. Missing upstream access
  stays visible.

## Verification requirements and evidence

EVS-1 applies each applicable method to the component and scoped claim.
Its adopted text defines the full gates. These references map the methods
to their responsibilities so a configured or absent gate remains visible.

| Scope | Applicable gates and records |
| --- | --- |
| Source, interface and baseline | Pinned compiler, fmt, Clippy, locked builds, nextest, doctests, dependency and architecture enforcement with negative fixtures, and affected platform and feature profiles. Keep parameterized cases, reviewed snapshots and deterministic mock adapter faults using rstest, insta, mockall or applicable owned fixtures. |
| Production-linked proof | Lean 4 and Mathlib with pinned hax/Charon/Aeneas, source/extraction/toolchain provenance, generated drift, theorem association and reviewed axiom/dependency audit. Keep extracted `Generated/` separate from authored `Proofs/`. Reject placeholders or unreviewed assumptions in the required theorem closure. Record unsupported extraction. |
| Bounded and independent verification | Kani on actual Rust, documented bounds and reachable premises with unwind checks enabled. TLA+/TLC for independent system/crash models, explicit fairness when used, deadlock and invariant checks, negative controls and production replay of counterexamples. |
| Test depth and failure sensitivity | Independent proptest histories and persisted shrinks, cargo-fuzz/libFuzzer on untrusted inputs with retained corpus and bounded budgets, Miri on supported paths, Loom/Shuttle on applicable scheduling, cargo-mutants and manual negative controls, and cargo-llvm-cov with reviewed denominators. |
| Native and performance | Native filesystem, fault, process-kill and actual power-loss tests on disposable profiles as required. Qualify IO ordering, storage errors and interruption separately. For applicable networking, include Wiremock/Toxiproxy, actual peers and route/fault evidence. Consider disposable service containers for service-backed tests. Use Criterion on equivalent verified operations and record resource/latency distributions. |
| Supply chain and release | Cargo-deny, cargo-vet, cargo-audit, controlled Renovate updates, Gitleaks and Trivy. Record unavailable scanners. Generate SPDX or CycloneDX SBOM and license/provenance notices per release profile. Reproduce portable locked builds and use protected signed artifacts. Scope shared caches by toolchain, lock and trust boundary if used. Optional static services supplement executable gates. |

ExaCopy's adopted EVS-1 sets at least two authored test/proof lines per
production line in safety-critical crates (target 2–3:1), more substantive
authored verification than production overall, 95% line and 90% branch
coverage targets for the pure safety core, and 85% line coverage for other
authored Rust. Measure authored nonblank code without generated data,
fixture dumps, vendor files or comment padding. Unsupported branch metrics
require explicit transition/branch evidence. Require coverage of declared
safety transition, guard and error categories. Target at least 90% viable
non-equivalent mutants killed in pure safety crates with zero surviving
known safety-invariant mutants. Record denominators and dispositions.
These are the ExaCopy pack's quantitative scope and targets.

Use [VERIFICATION.md](../../VERIFICATION.md) for implemented crate gates
and [TESTING.md](../../TESTING.md) for executed CI entry points. Required
release lanes include all applicable tests, proofs, reference and native
qualification, dependency reviews, performance, security and independent
review evidence. The underlying tools' availability, stage and evidence
status remain visible. A scoped non-applicability decision requires a
reviewer and justification. A failed, expired, missing or unexecuted
required result blocks the affected claim. Retain source hashes,
assumptions, oracle, profile, exact commands, tool versions, bounds,
status, exit code and artifact digests. Invalidate affected evidence when
code, assumptions, enabled features, tools, dependencies or oracle change.
