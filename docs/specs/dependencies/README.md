# Production dependency inventory

[graph.json](graph.json) records exact dependency versions and archive
checksums. The root lockfile supplies crates.io checksums.
[apfs-source.toml](apfs-source.toml) supplies the commit, tree and source
archive digest for the macOS-only Pomologie sibling. Each package has its
upstream repository, declared license expression, and build-script and procedural macro exposure. Each target
and profile records the incoming package edges and resolved feature union for
normal and build dependencies. Identical profiles for the same target share a
record. The profile and target definitions come from the [feature
matrix](../features/matrix.json).

The graph covers all production package roots. The experimental APFS, Windows
staging and WireGuard protocol profiles have separate target records. The
WireGuard profile builds an in-memory backend outside the CLI dependency graph.
Proof extraction, development-only feature
combinations, test-only dependencies and engineering roots are covered by the
broader workspace supply-chain checks. Target resolution records build inputs
for the selected target, including inputs compiled on the host. Native execution
and OS, filesystem and CPU qualification require their respective test lanes.
The [CLI release SBOM](../../supply-chain/README.md#unsigned-cli-rebuild-evidence)
identifies the inputs observed in actual builds of the selected binary.

[suitability.toml](suitability.toml) explains each package's role. Its
direct and transitive dependency assessments bind to exact archive checksums and record
release observations, security history, unsafe boundaries, resource and
input contracts, verification coverage and replacement implications. The
2026-11-25 registry release observations use the local crates.io index. Registry security history
uses the cached RustSec advisory database revision
`263a4d951a0867d4bddc29dddd6d59427c78f9a7`. Those observations are dated
inputs to suitability review. Current source, license, advisory and maintenance
checks belong to the review of the version under consideration.

Each suitability record lists its remaining review gaps. An empty list records
no outstanding gaps within that assessment's stated scope. Cargo Vet and native
qualification retain their own criteria and evidence. For transitive packages,
a purpose entry identifies the reason for inclusion, and an absent assessment
indicates an open suitability entry in this inventory. Existing exact-version
local and peer audit records live in [supply-chain](../../../supply-chain/README.md)
with their original scope and reviewer attribution. The locked Cargo Vet check
determines whether those records cover the required criteria. License notices,
permissions and exceptions follow [cargo-deny policy](../../../deny.toml) and
the packaged license texts.

Run from the workspace root with Python 3.12 or later and the pinned Rust
toolchain. Place a clean checkout of the exact commit in
`../pomologie/apfs` before running Cargo on any target. Check the sibling
with `python3 -B tools/apfs_source.py`. The `--fetch` form provisions an
absent sibling by fetching that exact revision. CI records a provisioning
failure if the revision is unavailable. Local evidence can use an existing
verified checkout while remote provisioning remains blocked.

```sh
python3 -B tools/dependency_review/check.py
python3 -B -m unittest discover -s tools -p '*_test.py'
```

Use `--offline` when the locked inputs are already in the Cargo cache.
`--emit-graph` prints a candidate snapshot for review. Inspect the graph and
lockfile diff, update the affected exact-version assessments, and run the
[workspace supply-chain checks](../../../supply-chain/README.md) before admitting
a change. A passing graph check establishes that the records match the
selected locked inputs and that their required fields are present. Review
gaps stay visible in the check output, and Cargo Vet provides its own gate.
