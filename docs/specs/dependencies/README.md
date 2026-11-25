# Production dependency inventory

[graph.json](graph.json) records the exact versions and archive checksums resolved
from the root lockfile. Each package has its upstream repository, declared
license expression, and build-script and procedural macro exposure. Each target
and profile records the incoming package edges and resolved feature union for
normal and build dependencies. Identical profiles for the same target share a
record. The profile and target definitions come from the [feature
matrix](../features/matrix.json).

The graph covers all production package roots, including the default-off APFS
transfer library on macOS. Proof extraction, development-only feature
combinations, test-only dependencies and engineering roots are covered by the
broader workspace supply-chain checks. Target resolution records build inputs
for the selected target, including inputs compiled on the host. Native execution
and OS, filesystem and CPU qualification require their respective test lanes.
The [CLI release SBOM](../../supply-chain/README.md#unsigned-cli-rebuild-evidence)
identifies the inputs observed in actual builds of the selected binary.

[suitability.toml](suitability.toml) explains each package's role. Its
direct dependency assessments bind to exact archive checksums and record
release observations, security history, unsafe boundaries, resource and
input contracts, verification coverage and replacement implications. The
2026-11-25 release observations use the local crates.io index. Security history
uses the cached RustSec advisory database revision
`263a4d951a0867d4bddc29dddd6d59427c78f9a7`. Those observations are dated
inputs to suitability review. Current source, license, advisory and maintenance
checks belong to the review of the version under consideration.

The suitability records have outstanding review gaps. For transitive packages,
a purpose entry identifies the reason for inclusion, and an absent assessment
indicates an open suitability entry in this inventory. Existing exact-version
local and peer audit records live in [supply-chain](../../../supply-chain/README.md)
with their original scope and reviewer attribution. The locked Cargo Vet check
determines whether those records cover the required criteria. License notices,
permissions and exceptions follow [cargo-deny policy](../../../deny.toml) and
the packaged license texts.

Run from the workspace root with Python 3.12 or later and the pinned Rust toolchain.

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
