# Pinned local transport sources

ExaCopy resolves two experimental transports from verified sibling
directories at `../local-deps/boringtun` and `../local-deps/russh`.
Their crate versions and Cargo feature selections match the registry inputs.
The source pin distinguishes modified code from the original registry packages.
Russh also serves the existing ring-only development fixtures in
`exacopy-cli` and `exacopy-sftp`. The normal production dependency on Russh
remains scoped to `exacopy-ssh`.

Run `python3 -B tools/transport_source.py --fetch` before using Cargo, or pass
`--crate-cache /absolute/path/to/registry/cache/index.crates.io-...` to rebuild
from an existing cache of the two original `.crate` archives. Run the script
without arguments to verify an existing checkout. It refuses incomplete,
edited, substituted, or symlinked source and binds each archive to its exact
registry checksum, upstream commit, repaired Git commit, tree, and archive hash.
Installed-checkout verification reapplies the pinned edit and notice to the
exact parent tree in an isolated Git index. The original compressed registry
archive hash is checked during reconstruction or when `--crate-cache` is
supplied to verify. The checked-out Git tree does not contain the original
registry compression bytes.
The pin and retained repair and license inputs are in
[`specs/dependencies`](../../specs/dependencies/transport-source.toml).

The package manifests are unchanged registry-normalized manifests. This avoids
activating unpublished upstream workspace siblings or changing package feature
selection. The checkout is made from the pinned published archive, the reviewed
behavioral repair, a separate modification notice patch, and the pinned
upstream license. The reconstructed commit identities
are local provenance records and are not upstream release commits.

## Review boundary

- BoringTun 0.7.1 adds transport key and operation attribution, age/counter
  observations, and a bounded session-retention seam. Existing cryptographic
  primitives and the reviewed caller's route and generation limits remain
  separate invariants.
- Russh 0.65.4 adds an application callback for the verified host key on
  rekey, before installing the new encryption keys. The caller remains
  responsible for applying its exact verified key policy. The selected
  consumer rechecks the pinned key and the connection's selected trust
  snapshot on every rekey before admitting new keys or pending data.
  Credentials remain exclusive to initial authentication. A confirmed newer
  WireGuard key can renew its bounded epoch without replacing the route or
  TCP stream; each retained key still has its own age and work bounds.
- Cargo Vet's path-dependency mode cannot bind the modified source bytes to
  an audit. The two version-scoped policies classify the path inputs for
  Cargo Vet only. The exact worktree, source review and activation profile
  are governed by the separate provenance and dependency inventory gates.
  Registry transitives keep their usual checks. A registry audit or a
  package name does not certify either modified source.
- The main Cargo audit keeps its registry transitive scope. The dependency
  job also scans a separately generated lockfile with the two exact upstream
  registry versions and checksums. This keeps the advisory scan visible
  when Cargo's path-source rows carry no registry source. A base finding
  fails the gate pending a disposition tied to the exact repaired commit.
  A passing upstream scan provides no audit of the repair.
- Default CLI release artifacts do not activate these transports. Build
  provenance records the verified path manifests needed by Cargo metadata.
  An SBOM includes a repaired source only if Cargo reports compiling it.
  Product routing, qualification, and longer-lived transfer behavior are
  separate activation gates.

The [BoringTun upstream tree](https://github.com/cloudflare/boringtun/tree/051c9d47dc9c5cb36e461b7d36dcd673820dc98b)
and [Russh upstream tree](https://github.com/warp-tech/russh/tree/4977b1afba8802137ac93f3e2c8bf916c35f437c)
provide the original license attribution. Retain the applicable license and
source-change notices with any approved distribution.
