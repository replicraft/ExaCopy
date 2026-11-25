# Consolidated architecture reconciliation

The consolidated supplemental requirements supplied on 2026-11-25 replace
the earlier supplemental prompts. The subsequent foundational-library
amendment replaces the proposed `exacopy-types` and foundational
`exacopy-codec` with `exacopy-core`. Existing safety guarantees, product
requirements and applicable EES-1/EVS-1 obligations remain mandatory.
This record is the initial implementation audit required by section 52;
it does not certify completion of the restructuring or release gates.

The exact supplied consolidated input has SHA-256
`0da43f03b167c8425e967f0e9a6720c27ab3c03ac99b66ed8cb979a9deef0cdf`;
the later core amendment has SHA-256
`37945edd8851e71c9cf9e4a734d60adac6ef2d3f8e17621b0a74ecd4a773fa91`.

## Governing decisions

- Product executables belong under `apps/<package>/`; root `xtask/` owns
  developer executables. Library package directories use their complete
  package name under the appropriate `crates/<responsibility>/` group.
- `exacopy-core` owns genuinely shared, dependency-light primitives and
  forbids unsafe code. The safety model remains independently verified.
  Format-specific Plan and manifest serialization has a format owner.
  Do not create placeholder packages to fill the target tree.
- Engines receive capabilities. Applications select concrete adapters.
  Native handles and observations belong to platform implementations;
  native composition does not justify putting workflow policy there.
- Testkit remains `crates/engineering/exacopy-testkit`. Package-owned
  tests, fuzzing and verification stay with their owners when relocated.
- Retain one workspace, root lockfile, Rust 1.100.0, edition 2024,
  resolver 3, inherited dependencies/lints, declarative module roots,
  thin executable entrypoints, hard tabs and the 500-line source ceiling.
- Preserve failure evidence and distinguish abstract proof, executed
  implementation tests and native qualification. A path move cannot
  refresh historical evidence or expand a safety claim.

The [standards adoption](standards.md) identifies canonical revisions
previously inspected and unavailable material. These supplemental rules
are ExaCopy requirements; they are not attributed to those canonical
documents. The current implementation priorities remain remote transport,
recovery, cross-platform operation, protected operations, synchronization
and installation. GUI remains last in that sequence; the broader product
scope is retained.

## Initial audit at `a73c649`

| Finding | Correction and acceptance boundary |
| --- | --- |
| CLI executable is under `crates/clients/cli`. | Move to `apps/exacopy-cli`, update workspace, all consumers and Cargo-target-aware architecture checks. |
| Most library directories omit their package prefix and use superseded group names. | Mechanically relocate existing packages in reviewable commits; update active contracts, tools, proof paths and CI together. Preserve revision-bound historical evidence. |
| `exacopy-engine` selects Linux/APFS adapters, and the matrix expressly permits the dependency. | Move actual native assembly to the application, remove remaining generic policy from that assembly and prohibit engine-to-adapter dependency closures with negative fixtures. Do not retain an empty compatibility engine. |
| APFS bootstrap admission, stage retry and one-shot publication decisions remain in native composition. | Move ordering and state decisions into supplied-capability transfer coordinators; preserve native error projection and receipt bytes. Run native and deterministic refusal regressions. |
| Named Linux read-view binding lives in the composition crate. | Move the native held-name implementation and its tests to the platform owner. |
| Foundational codec contains public Plan and manifest formats; endpoint and manifest duplicate component validation. | Establish a real shared core primitive, move format ownership, preserve validation precedence, canonical vectors and explicit version refusal. Keep extracted range code in place until its proof correspondence can migrate atomically. |
| Transfer journal capabilities expose `std::fs::File`; CLI profile and Plan bundle code directly performs native operations. | Track as further capability/adapter work. Moving directories does not resolve these boundaries. |
| Existing syntax-aware source checks are useful, but package placement assumes every application is under `crates/`. | Enforce applications versus libraries using Cargo target metadata, complete package directory names and invalid fixtures, including renamed, optional and target-specific dependencies. |
| CI does not yet execute all newly introduced SSH/WireGuard optional test profiles. | Add explicit bounded native profile lanes; compilation alone is insufficient. |
| Windows SSH with its feature enabled has not executed natively. | Keep the qualification open. The macOS cross-build lacks MSVC SDK headers for Ring; no installed OpenSSH client fixes that build environment. |
| Dependency suitability and release evidence remain incomplete. | Preserve open dependency reviews, native filesystem/Windows qualification, supply-chain and release gates. Do not score these as passed based on restructuring. |

Existing testkit, crate-local Lean/Kani/TLC ownership, pinned toolchains,
source-size/declarative-root checks, feature isolation and versioned
contract inventory provide working foundations to retain. Their presence
does not imply every supplemental obligation has executed evidence.

## Integration order and ownership

1. Record this audit and reconcile contributor instructions.
2. Correct remaining generic Mac workflow ownership and native Linux
   read-view placement with behavior-preserving tests.
3. Establish real core sharing and format ownership, keeping proof-linked
   implementation changes separate from mechanical moves.
4. Move applications and fully prefix existing library directories.
   Serialize manifests, lockfile, shared contracts and inventory updates.
5. Enforce the corrected dependency direction and placement with valid
   and deliberately invalid fixtures. Reconcile active documentation,
   verification dispatch and CI profiles.
6. Verify the final clean integrated commit with workspace checks and
   affected proof gates, then review remaining findings and evidence.

Independent contributors own Linux composition, Mac workflow inversion,
architecture enforcement, core/format boundaries, portability and
verification audit. Their private patches integrate serially. Only the
parent updates shared manifests, lockfile and common inventories. No
push, release, VM recreation or sibling-repository change is implied.

## Corrected package placement

The application now resides in `apps/exacopy-cli`, including native
capability assembly and its integration tests. There is no empty
`exacopy-engine` compatibility package. Actual workflow decisions remain
in `crates/engines/exacopy-transfer` and exact comparison in
`crates/engines/exacopy-diff`.

Existing libraries use their complete package directory names under
`foundation/`, `interfaces/`, `platform/`, `net/`, `formats/`, `storage/`
and `engineering/`. Only implemented responsibilities have packages.
The shared component validator and its P-013/fuzz ownership now live in
`exacopy-core`; Plan and manifest formats have separate owners. Their
independent oracle paths and frozen vectors were preserved and repaired
where relocation broke imports. The selected dependency features remain
unchanged; the broader `minicbor/alloc` selection was rejected in review.

The schema-2 dependency checker derives composition roles from canonical
package locations and inspects Cargo declarations, including aliases,
optional/target-specific edges and engine dependency closures. `crates/net/`
owns transports. Endpoint integrations under `crates/adapters/` may use a
transport through an exact normal dependency pair listed in the
[dependency matrix](../../specs/architecture/dependencies.toml). The pair
also requires the normal group allowance. Applications with an executable
target select the concrete adapters and transports. The engine closure check
follows workspace edges and rejects concrete adapters, transports,
applications, and declared concrete external dependencies. Negative fixtures
cover the transport boundary, misplaced executables, alternate binary source paths,
cross-package target sources and invalid fuzz workspace exemptions.
Source review remains necessary for capability authority and macro
behavior; a permitted graph does not prove workflow correctness.

Linux profile seed acquisition, exclusive initialization, held identity,
bounded native entropy and file/directory barriers now belong to the platform
adapter. The CLI retains path selection, signing-key construction, versioned
owner/root identifier derivation and error projection. The move preserves the
existing checks and bytes. Linux-target lint compiles the synthetic fixtures;
native Linux execution of this extraction remains unqualified. Plan bundle
effects and the remaining identifier policy still need their ownership moves.

Historical evidence retains its recorded revision and paths. Current
source links and reproduction entry points follow the corrected layout.
When reproducing an older pinned revision, use that revision's package
inventory. Remaining native qualification, dependency review and journal
I/O capability findings from the initial audit are reviewed separately.

## Typed journal segment boundary

Journal framing and durable append ordering now consume the endpoint's
`JournalSegment` capability rather than a native file. The native adapter
owns the descriptor, file barrier and namespace lease. Linux fresh segments
retain the locked open file description; recovered segments borrow the
exclusive recovery writer lease. Darwin segments retain the managed job
directory and check its held identity around `F_FULLFSYNC`.

The journal retires its writer after an uncertain inspection, write or
barrier. A successful append reports the selected file barrier only;
namespace persistence and power-loss qualification remain separate. The
affected native macOS tests and strict host checks passed, and Linux
consumers passed strict cross-compilation. This extraction does not supply
new native Linux execution or power-loss evidence.
