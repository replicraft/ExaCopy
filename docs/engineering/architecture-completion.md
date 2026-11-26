# Architecture completion status

Reviewed 2026-11-26 at `8633ee7ca061a56f36902f554e36820f567fa8c8`.
This revision implements the repository restructuring and the listed
ownership corrections. Native acceptance, release approval and the
remaining assurance gates are open. The [reconciliation](architecture-reconciliation.md)
identifies both governing supplement digests and retains the initial
discrepancies at `a73c649`. This report records the §§57–58 review against the reviewed
source and recorded results. The full numbered audit remains in local
engineering evidence. The evidence table and remaining-work section include
later revision-specific updates through `1b89477`. The scores remain tied
to the original review.

## Changes and affected repositories

| Initial discrepancy | Correction in the reviewed tree |
|---|---|
| Executable and native assembly shared the library tree | `crates/clients/cli` moved to `apps/exacopy-cli`. The CLI absorbed concrete assembly from `crates/runtime/engine`; the latter package was removed. Linux named reads moved to platform and managed APFS policy moved to transfer. `0d1d9ed`, `d7acdf2`, `93ce6de`, `a210922`. |
| Foundational codec and repeated filename and identity primitives | `crates/core/model` became `foundation/exacopy-model`. The foundational codec was replaced by `formats/exacopy-plan` and `formats/exacopy-manifest`. New `foundation/exacopy-core` owns shared raw component admission and job, entry, run and stage identities. It inherits a minimal UUID dependency and forbids unsafe. `94837ee`, `fe47b44`, `d6761ab`. |
| Inconsistent domain placement and production dependency direction | `endpoints/{endpoint,platform}` moved to `interfaces/exacopy-endpoint` and `platform/exacopy-platform`. `operations/{diff,transfer}` moved to `engines/exacopy-{diff,transfer}`, `network/{ssh,wireguard}` to `net/exacopy-{ssh,wireguard}`, and `storage/{content,journal}` to `storage/exacopy-{content,journal}`. These paths are under `crates/`, alongside the existing engineering testkit and new `adapters/exacopy-sftp`. The root `xtask` enforces package placement, engineering isolation, and role and target dependency rules with invalid fixtures. `a210922`, `b6f77d1`, `4ae9d69`. |
| Native effects and format policy crossed capability boundaries | Transfer orders work through endpoint capabilities. Native journal segments retain their lease and barrier semantics while storage owns framing and uncertain-writer retirement. Platform owns Linux profile acquisition and Plan bundle effects; formats own Plan bundle encoding and timestamp/ID policy. `038fcee`, `ddf2798`, `0d43acc`, `99ab702`. |
| Verification owners, optional CI and reproducible development tooling needed explicit controls | The workspace requires six registered owners with ledgers, dispatchers and minimum gate kinds. CI retains separate nextest reports for optional profiles and release. Local and Linux CI compilation can opt into isolated sccache. Core has an owned benchmark and reproduction guide. `0414aa1`, `8d461bc`, `339f27b`, `457c50e`, `8633ee7`. |

The [dependency policy](../../specs/architecture/dependencies.toml) and
[locked production inventory](../../specs/dependencies/graph.json) describe
the updated graph. Applications compose adapters, transports and engines.
Engines depend on capability, format, storage and foundational owners;
the SFTP endpoint adapter has an exact allowance to use the SSH transport.
Core stays below the model. The safety requirements, contract versions
and evidence labels remain governed by their existing specifications.

[EES-1 and EVS-1 adoption](standards.md#source-revisions-reviewed)
records the pack fingerprints, dmgez `9b5aec7` with exact EES-1 and EVS-1
blobs, TableCraft `17d8389`, VBA `95425ac`, EarthCraft `bad15e2`, and
Relay `79dcdb6`. Canonical Dockhand sources were unavailable. The workspace
uses one application lock, Rust 1.100.0, edition 2024, resolver 3, inherited
dependency and lint policy, hard tabs and declarative module roots. Proofs
and fixtures stay with their owners. Shared contracts and lock changes
integrate serially, with failure evidence kept by revision.

[APFS](../../specs/dependencies/apfs-source.toml) is an independent companion.
The reviewed baseline used `fdcc3ea`; `5e936f0` advanced the selected pin to
`0266afa`; the sealed-handle metadata follow-up selected `fc71ded` and removed
the duplicate consumer descriptor. The current pin selects public `af97d385`,
which provides observation-only recovery reopening. Consumer adoption is
pending. The bounded [companion audit](filesystem-companion-boundary-audit.md)
reviewed APFS and HFS+ source without changing either. At `1660ab3`,
[BoringTun and Russh](../supply-chain/local-transport-sources.md) became
locally reconstructed, reviewed dependencies pinned to repair commits
`ea14f16` and `7bcc7bd`. Their upstream version, registry archive, source
tree and notices remain recorded. The repairs are local source inputs.

## Executed checks and evidence limits

| Revision and execution | Result |
|---|---|
| Focused integration through `8633ee7` | `cargo fmt --check`, `cargo test --locked -p xtask`, strict xtask Clippy and `cargo run --locked -p xtask -- check` passed. All 72 xtask tests passed. The checker reports 28 declared verification gates. Plan and transfer passed 112 native macOS tests plus strict Linux cross-Clippy; Linux CLI refusal fixtures compiled. |
| Pinned transport integration through `8633ee7` | `cargo test --locked -p exacopy-ssh --features experimental-ssh` and `cargo test --locked -p exacopy-wireguard --features experimental-udp` passed 49 SSH cases with five ignored and 18 native macOS WireGuard cases using loopback. The first SSH rekey attempt failed; the explicit strict callback restored the typed refusal and the unchanged regression passed. Strict selected host/Linux Clippy passed. The feature-matrix tool checked Linux, macOS and Windows dependency graphs. Exact pinned sibling graph/suitability verification covered 208 versions across three targets, with 67 suitability assessments and 141 without a suitability entry. |
| Tooling and release development through `8633ee7` | 48 tool tests and 12 mocked release controls passed. Actionlint and affected shell syntax checks passed. The signed candidate and installer workflow definitions are present. Hosted execution for the revised workflows and production publication remain pending. |
| Core benchmark at `8633ee7` | `cargo bench --locked -p exacopy-core --bench unix_component` executed all three warm cases in the host optimized profile. Batch medians were 9.326 ns for a 10-byte accepted input, 32.609 ns for a 255-byte accepted input and 33.622 ns for terminal-NUL refusal at 255 bytes. This adds a baseline for the pure validator. Cold-start, I/O and before-and-after performance evidence remain unmeasured. |
| Follow-up at `1b89477` | The all-feature macOS workspace run passed 906 tests with 27 skips after 13 loopback-dependent WireGuard failures under sandbox restrictions. The unchanged rerun with loopback access passed. The owner inventory lists eight crates. The architecture checker reported 36 declared gates. The checker result covers the structure of the declarations. |
| Historical exact integration `c8e3bd0` | The macOS workspace run passed 881 tests with 25 skips. Formatting, strict Clippy, doctests and architecture policy passed. All 30 declared gates passed at that revision, including 23 Rust, four TLC, one Lean and two Kani gates. The original TLC sandbox bind failures and the unchanged retry are retained. |
| Historical full integration `8503dd3` | The locked all-feature workspace nextest and doctests executed on macOS. Nextest passed 804 tests with 21 skips after seven sandbox loopback failures were rerun with loopback access. Strict Linux cross-Clippy passed. The local APFS mounted crate matched the pin; the entire sibling checkout was at a different revision. |
| Historical exact pinned `15e3c4e` | The full native workspace run passed 739 tests with 21 skips; all 21 declared Rust/Lean/Kani/TLC gates passed. Reproduction and evidence ownership follow the [verification guide](../verification.md). |
| Native Linux ARM64 subset and candidates | In the documented Docker environment, 887 baseline cases passed, three Plan cases refused a subtree mount, and 16 were ignored. Four Plan cases passed in the separate overlay run. The frozen adapter candidate passed 86 cases. Five publication fixtures refused before effects because the required procfs observation crossed a mount. |

Commands, exit statuses and failure logs are retained locally under
`target/agent-evidence/`, including `integration-8633ee7`,
`root-integration-8503dd3`, `final-pinned-verification/15e3c4e`,
`native-linux-arm64-fccd020`, `integration-c8e3bd0` and the
`latest-apfs-workspace-tests*.log` pair. The full 36-gate set at
`1b89477` still needs integrated execution and exact-revision evidence.
The [remote readiness record](remote-transfer-readiness.md) describes
environment conditions and the remaining end-to-end cases.

## Review dimensions

Scores use a ten-point design-review scale. A 10 requires complete
in-scope controls and current independent evidence. A 9 requires a
resolved architecture boundary with direct validation and only routine
follow-up. An 8 has strong scoped controls with a meaningful evidence or
feature gap. A 7 has a working boundary with substantive implementation
or acceptance work. A 6 has component evidence with the integrated path
still blocked. The supplement targets at least 9 for every applicable
dimension. The open dimensions below remain below target. Scores convey
review judgment. Only the applicable checks support safety and release
claims.

| Dimension | /10 | Evidence and rationale |
|---|---:|---|
| Repository organization | 9 | Canonical application and library paths, one workspace and no empty compatibility package. Placement has negative fixtures. |
| Dependency architecture | 9 | Role and closure checks passed with exact graph inputs. Concrete adapters and transports stay outside engine closures. |
| Modularity | 8 | Journal, Plan, model and endpoint seams have real owners. APFS-native mechanisms still overlap the companion. |
| Maintainability | 8 | Scoped domain modules and checked ownership ease updates. Companion migration and reconciliation of remaining owner prose are open. |
| Rust engineering compliance | 8 | Pinned toolchain, inheritance, strict lint and format checks cover changed packages. Full-suite exact-tip assurance and source-wide verification denominator remain open. |
| Source organization | 9 | Real Cargo targets and syntax-aware checks enforce thin entrypoints, declarative roots and file-size policy. |
| Type safety | 8 | Typed identities, capabilities and checked Plan inputs bind operations. Remote application authority has remaining assembly and runtime evidence. |
| Error handling | 8 | Refusal, ambiguous effect and barrier failures are distinct. Full command-level retry and reconciliation cases remain open. |
| Unsafe-code isolation | 8 | Core forbids unsafe and native calls have platform owners. APFS raw ownership and native NTFS assumptions need further work. |
| Data preservation | 8 | Linux no-clobber, independent read-back and incumbent fixtures support the local profile. Native remote publication and complete metadata fidelity are open. |
| Crash consistency | 7 | Journal barriers, replay and injected faults exist. Integrated interruption acceptance and physical power-loss profiles remain open. |
| Recovery | 7 | Linux local inspect, finish, retry and resume exist. Writable remote lifecycle composition and exact interrupted recovery remain open. |
| Concurrency correctness | 7 | Held leases, generation fences and bounded diff joins have scoped tests and a TLC model. End-to-end remote cancellation and scheduling evidence are open. |
| Network resilience | 6 | Bounded retry/source/UDP components execute. Route-owned connection supervision, renewal and automatic verified range resume are pending. |
| Authentication | 7 | Verified SSH host identity, explicit trust and bounded protected key admission are integrated. Native protected-file and full credential lifecycle remain open. |
| Authorization | 8 | Typed model transitions, sealed intent and a final native grant fence encode the boundary. The product remote command has no qualified effect path. |
| Cryptographic integration | 7 | Bounded signed formats and reviewed repaired transport inputs have vectors and provenance. Cryptographic transitives and full route/rekey acceptance remain open. |
| Formal verification | 8 | Six owner ledgers with actual Lean, Kani, TLC and Rust paths and scoped historical evidence. The complete 28-gate run is open. |
| Test effectiveness | 8 | Deliberate proof and architecture omissions, fault fixtures, independent vectors and persisted failures. Complete current coverage, mutation and denominator evidence remain open. |
| Independent correctness evidence | 8 | External OpenSSH, format oracles, native comparison and extracted model results cover distinct claims. Full shipped transport, platform and installer parity are open. |
| Platform portability | 7 | Linux local CLI and measured macOS comparison scope are explicit. Windows and broader macOS paths need native acceptance. |
| Filesystem fidelity | 7 | Strict local admission, selected metadata and explicit omission receipts exist. APFS equivalence boundaries and broader native metadata remain open. |
| Protocol interoperability | 7 | OpenSSH and keyed UDP fixtures exercise bounded profiles. A complete routed and renewable production connection remains open. |
| Performance | 7 | Scoped verified operation baselines, a core microbenchmark and isolated cache support exist. Full media/network baselines and equivalent-profile comparisons are open. |
| Resource consumption | 7 | Bounded messages, windows and segment sizes. Larger inventories, end-to-end worker bounds and native resource evidence remain open. |
| API and format compatibility | 8 | Version inventory, frozen vectors and explicit refusal preserve supported contracts. Full product migration and deployed old/new runtime cases are open. |
| Documentation | 8 | Current contributor, architecture, verification and scoped reports identify owners and limits. Some root documentation entrypoints and stale descriptions remain. |
| Build reproducibility | 8 | Exact source pins and locked three-target graph checks passed. Current full exact-tip and signed-artifact reproductions are open. |
| Supply-chain integrity | 7 | Source repair provenance, scans and SBOM policy are configured. Suitability coverage, deployment review and exact signed artifact evidence remain open. |
| Release safety | 7 | Signed packaging, verified draft-ID selection and owned launcher lifecycle have scoped controls. Actual protected hosted signing, promotion and native install evidence remain open. |
| Coding-agent coordination | 9 | Disjoint ownership, serialized shared changes, enduring evidence and scratch cleanup are recorded. |
| Implementation readiness | 6 | Linux preserve-mode local work is usable within scope. Remote CLI, native qualification and production release still have concrete blockers. |

## Remaining implementation and acceptance

After the scored baseline, `7753fa8` integrated the bounded TCP carrier,
verified SSH rekey, per-key WireGuard renewal, one outstanding SSH keepalive
and exact-session cancellation. P-052 checks a bounded in-memory renewal case.
At `c8e3bd0`, P-053 added a pure genesis admission gate with 131,072
reported-fact cases. The 30-gate execution at that revision covers those
obligations within their stated bounds.

At `1b89477`, the paired baseline leaf codec and the pure genesis predicate
are implemented. Genesis still needs native paired observations, an
authenticated workflow root and dependency closure, and immutable publication
into separately authorized output. For remote recovery, the retained-prefix
verifier, continuation model and signed kind-40 codec are implemented.
Continued replay, tail append authority and finalization remain separate from
the current fresh-attempt command. [Registered contracts](../../specs/contracts/versions.toml)

- **APFS companion.** The source and live staging/publication adapters use
  the companion mechanisms, including the strict stage ACL predicate and
  explicit partial-read diagnostics. The pinned `af97d385` companion supplies
  `ReopenedStage` for restart read-back. Adoption must keep the reader's
  borrows of the event anchor, held directory and matching lease live through
  read-back and revalidation. ExaCopy still checks protected ancestry, both
  selected names, recorded identity and strict metadata. Preserve its current
  post-open initial and final live metadata checks when projecting the
  companion observations. The strict copy-through-receipt profile still needs
  native qualification. The bounded audit found no tracked HFS+/HFSX production
  implementation. [Companion audit](filesystem-companion-boundary-audit.md)
- **Current support.** Linux exposes exact comparison, single-file manifests,
  preserve-mode copy and local recovery within stated profiles. macOS offers
  explicit owner-managed APFS comparison and an experimental transfer library.
  NTFS comparison is feature-gated; native Windows qualification and general
  copy/recovery completion remain open. Linux source builds expose the
  opt-in SSH/SFTP download and fresh-attempt remote resume commands, with
  a separate embedded WireGuard feature. The command requires independently
  signed qualification for the exact running build, route and native
  destination. It reports explicit metadata omissions and refuses writable
  restart after publication intent. Current native interruption,
  reconciliation, filesystem qualification and production acceptance remain
  open. [Experimental SSH download](../../apps/exacopy-cli/README.md#experimental-ssh-download-on-linux)
  · [Remote acceptance](remote-transfer-readiness.md)
- **Assurance and release.** Run the current locked workspace and all declared gates
  against the exact pins, with original failed and blocked results retained.
  Execute hosted optional CI and release jobs and the required native Windows,
  macOS/APFS and Linux destination profiles. Resolve required dependency
  suitability, Cargo Vet, signing trust and installer lifecycle evidence
  before publication. Process-crash and power-loss qualification remain
  separate. [Verification](../verification.md)
  · [Release workflow](release-ci.md)
  · [Dependency evidence](../supply-chain/README.md)
- **Remaining current priorities.** Protected operations and synchronization
  remain in the current scope, with their [roadmap](../roadmap.md) safety
  dependencies. The pure sync classifier and baseline model do not establish
  a working synchronization executor. The repository architecture supplies
  no replacement or deletion authority by itself.
- **Later product work.** Backup/repository and deduplication are deferred.
  GUI work comes after the current CLI priorities. Other architecture-pack
  product capabilities retain their dependencies and require separate
  implementation and acceptance evidence.
