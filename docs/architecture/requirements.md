# Requirements traceability

The [local requirements trace](../specs/requirements/local.v1.toml) maps
selected requirements, acceptance cases and invariants from ExaCopy
Architecture Pack baseline 2.1 to repository evidence. It fingerprints the
four design inventories that define those IDs. The local pack stays under
`docs/temp/`. The trace describes the implemented portions of the design
and the next capability boundaries. Requirements without a trace entry
retain their design status.

Each entry binds the listed IDs to the behavior and limits stated in
`scope` and `limits`. The same ID can appear under several entries when
the model, adapter and end-to-end paths cover different parts of a
requirement. A link to A-028, for example, can identify directory barrier
and receipt checks without establishing power-loss durability.

## Local evidence

| Scope | Owners and boundary |
| --- | --- |
| Preserve-mode authorization and checked ranges | The [model manifest](../../crates/core/model/verification/obligations.toml) owns P-001–004. The Rust replay exercises the TLC counterexample. Lean and Kani cover the single-range arithmetic guard. |
| Component admission and held roots | The [core manifest](../../crates/foundation/exacopy-core/verification/obligations.toml) owns P-013 for the Unix byte validator. Native Linux tests cover descriptor-relative admission. Windows tests cover lexical UTF-16 and reserved names. Native Windows handle access and publication are specified. |
| Linux single-file copy, inspection, finish, resume and retry | Transfer, platform, journal and CLI tests exercise exclusive publication, independent read-back, signed job evidence, torn records, restart and range revalidation. The [verified staging guide](../verified-staging.md) records process-kill boundaries. The [ext4 guest run](../specs/performance/evidence/linux-ext4-copy.json) records an independent byte validation and reference controls. Receipts report unconfirmed durability. |
| Linux and managed APFS exact comparison | The [diff manifest](../../crates/operations/diff/verification/obligations.toml) owns repository obligation P-036 for result ordering and joining over fixed range observations. Native cases cover live observations. The [managed APFS differential](../specs/compatibility/evidence/macos-apfs-differential.json) records reference and negative-control outcomes. |
| Managed APFS copy and inspection | The [feature matrix](../specs/features/matrix.json) identifies the experimental library. Native tests cover private staging, exclusive rename, incumbent preservation and inspection. The strict end-to-end fixture is blocked on the tested host by source metadata admission. CLI exposure and native process-crash and power-loss qualification remain open. |
| Workspace controls | The [verification guide](../verification.md) points to the configured check entry points and each crate's proof ownership. Review, qualification, and supply-chain status come from the scoped evidence records. |

The trace uses three coverage statuses.

- `implemented` means the scoped local behavior or engineering check has
  an implementation and evidence links.
- `experimental` means the scoped implementation has partial support under
  the indicated development profile.
- `specified` means the listed capability has a design scope and pending
  acceptance. The [roadmap](../roadmap.md) describes its dependencies.

An evidence entry identifies its owner, artifact and level. Test entries
name the function. Obligation entries name the record in the owning
crate’s manifest, which carries methods, assumptions, bounds and oracles.
`defined` marks a repository test, proof obligation, fixture or configuration.
`reported` points to an execution summary. `retained` points to a
revision-bound result whose outcome is recorded in the artifact. `blocked`
carries the reason a specific gate could not establish its scoped claim.
Native adapter tests, process-kill tests, and hardware qualification
answer different questions. Historical results apply to their recorded
revision, fixture, platform and settings.

## Maintain the trace

Update the affected entries when a work package changes scope, test or
proof ownership, or profile acceptance. Keep failures and blocked gates
visible when adding results. Record raw evidence using the [verification
policy](../verification.md). Use the [compatibility inventory](../specs/compatibility/inventory.v1.json)
for reference-specific expectations and the [performance workload
specification](../specs/performance/workloads.v1.json) for measurement
profiles.

Run the structural check with Python 3.11 or newer from the checkout.

```sh
python3 tools/requirements/check.py
```

When the baseline is present locally, the check also verifies its
fingerprints and confirms that the mapped IDs exist.

```sh
python3 tools/requirements/check.py --pack docs/temp/exacopy-architecture-pack
```

The check resolves evidence owners, paths, test symbols and obligation IDs.
Running the linked gates and reviewing their retained evidence establishes
the outcome.
