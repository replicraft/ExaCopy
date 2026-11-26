# Cargo registry candidate projection

The projector reads a full immutable ExaCopy commit and materializes the
existing default CLI as package `exacopy` with its ten internal library
packages. It stages standalone manifests and source in an absent output
directory. The repository workspace and root lockfile remain the canonical
build inputs. The projector never contacts or writes to a registry.

```sh
python3 -B tools/release/registry_projection.py \
  --commit "$(git rev-parse HEAD)" --output target/registry-projection
python3 -B tools/release/registry_projection_test.py
```

The manifest policy fingerprints parsed TOML values. Review full manifest,
feature and dependency changes before updating it. Changing workspace source
files alone does not require a policy update. The generated `projection.json`
records the commit, destination file hashes, dependency order, workspace lock
hash and its registry version/checksum inventory. It also records the
independent Pomologie `apfs-mounted` source pin. Source bytes come from Git
objects so changes in a worktree cannot enter the candidate. Packaged source
retains Linux comparison, manifests, plans, copy and recovery, plus managed
APFS comparison on macOS. The Windows default refusal profile is unchanged.
The ordinary workspace retains the experimental features, dev dependencies
and all test and proof lanes. Standalone package verification builds the
published targets without these development lanes.

Before any upload, use a private registry fixture to exercise the complete
candidate graph with Cargo 1.100.0. The Pomologie publisher must make an
exact registry-compatible `apfs-mounted` crate available. Verify its
provenance and `.crate` checksum against the recorded pin. Before proceeding
with a dependent package, verify the approved archive and checksum of each
staged dependency. Build and inspect a locked release on each supported
native platform. Check the resolved registry versions and checksums against
the workspace lock inventory and approved companion/internal artifacts,
including feature and compiler option parity with the workspace release.
Address dependency-audit and release verification findings before promotion.

Install each candidate with a fresh temporary Cargo home and install root.
Check the selected executable, help, version, Linux comparison, manifest
verification, read-only plan export, copy to an absent name, preserved
incumbent on refusal and recovery inspection. On macOS, verify managed APFS
comparison and its refusal without the managed flag. Include reproducible
archive digests and native results in the release evidence. A local archive
or passed fixture does not establish that the registry name is owned.
