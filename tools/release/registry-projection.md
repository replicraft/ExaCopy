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

## Optional transport projection

Use `--profile transports` to stage the preserved Linux SSH and embedded
WireGuard feature edges and the repaired BoringTun, Russh and Russh utility
libraries. The default command and its output are unchanged. The optional
projection verifies the selected commit's pins, locally reconstructed Git
archive bytes and exact repair/attribution lineage before it selects any
transport source. Use the existing pinned transport-source setup first.

The package names distinguish the downstream sources; their Rust crate
identifiers remain compatible with the existing consumers. Russh directly
depends on the renamed repaired utility, since Cargo strips workspace
patches from registry packages. All three downstream source archives carry
their original license and the corresponding ExaCopy modification notice.
The renamed Russh package reports its own name and version in the derived
SSH software identification string.

The projected CLI has four default-off features.

| Cargo feature | Intended command scope |
| --- | --- |
| `experimental-ssh-capture` | Linux experimental SSH acquisition |
| `experimental-ssh-wireguard` | Linux experimental SSH acquisition over embedded WireGuard |
| `experimental-linux-managed-sync` | Linux `sync-managed profile-identity`, plus `init` and `preview` on the admitted whole-ext4 profile |
| `experimental-windows-diff` | Windows `diff --local-ntfs` for live byte comparison on fixed local NTFS |

Managed sync retains the [existing Linux profile, private initialization
receipt and read-only preview](../../docs/engineering/linux-managed-sync-production.md).
Windows retains the [tested fixed-NTFS comparison
scope](../../docs/testing.md#windows-held-directory-ntfs-qualification).
The workspace native evidence applies to its recorded revisions, hosts
and selectors. A frozen registry candidate needs its own installed
command checks. Experimental APFS copy, Windows staging and copy, the
Windows SFTP capture SDK, and fixture features remain outside the projection.

A registry candidate requires the canonical approved `apfs-mounted`
archive from its publisher. An exact APFS source fixture is suitable for
private testing with a local registry.

Run `python3 -B tools/release/registry_transport_projection_test.py` with
the verified transport siblings available. Private locked install results
do not establish public registry availability or native transport
qualification.

### First public version

Choose one frozen profile and one exact source revision before publishing a
crate version. The profiles can produce different archives for the same
crate name and version. Select the transport profile for the first release
intended to include the four opt-in features, after its native, supply-chain
and publisher checks pass. Adding this profile after a default-only CLI
upload requires a new CLI version and new versions for any published
dependency artifacts whose contents must change.

The existing GitHub `v0.1.0` tag identifies user-testing revision
`104451ebfeeb344418ece53ad020e7cbafa72054`. A registry candidate from a
later commit has its own source and package digests. Before publishing,
review its version, package provenance and source revision together.
Existing user-testing assets only describe the source named in their own
provenance.
