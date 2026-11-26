# Decision: explicit genesis for one synchronization subject

**Status:** Proposed. The existing [classifier](sync-classification.md)
and P-041 are implemented. This decision defines the next read-only
planning slice. It requires no new wire allocations or enabled commands.

## Context

A two-way preview needs a common ancestor for the exact pair and selected
subject. The first observed match carries no prior action receipts. The
existing P-041 model exercises the classifier and a bounded successor
admission rule with a current predecessor and matching endpoint receipts.
Genesis needs a separate admission rule and evidence. This decision applies
pack ADR-039, ADR-096 and ADR-097 to one subject.

## Decision

On explicit request, create an immutable, owner-signed generation-one seed
only when two fresh, independent reads verify matching regular files at one
exact raw basename. The authorized left and right roots are ordered,
distinct directory children of one held parent on the same admitted
managed Linux mount and namespace session. Establish disjointness by held
identity and ancestry. Refuse root or file aliasing, symlinks, mount
crossings, unsupported entries and roots without the required stability
contract. A read-only handle can observe change and may update access time.
The evidence reports a live observation within the admitted profile.

Bind the owner/profile revision, ordered pair, native root and mount-session
identities, raw basename, selection and required metadata policy. Admit and
record a distinct native identity and an independently measured length,
BLAKE3 digest and required metadata digest for each side. Each measurement is
bound to its own held file and rooted name. Match lengths and both digests.
Check both roots and names before reading, recheck each file around its full
read and EOF probe, and recheck the pair together after both measurements.
Use the same stability conditions for the complete pair through signing and
artifact publication. A mismatch, absence, unsupported field, stale binding
or any incomplete observation blocks genesis and preserves both sides.

Compare actual mode, UID and GID in the same authorized Linux ownership
namespace. Require a regular single-link file and reject special permission
bits. Use modification and change observations for live stability checks.
Declare other metadata omissions explicitly. A shared future encoding must
fix the canonical metadata projection and digest domain before use. Digest
equality is conditional on the selected hash assumptions.

The seed contains one matched row, two complete present observations, a
null predecessor, and empty transfer-action, receipt and tombstone sets.
The seed records a common observation under its retained owner and scope.
It carries no live handle, change grant, successor authority or current
baseline pointer. Separate successful seeds for the same pair remain
immutable candidates. The planner selects one exact authenticated digest
explicitly. No timestamp, directory order, cache or prior signature chooses
which seed applies. Scope or mount-session changes require a new admitted
selection. Historical artifacts may still be inspected.

After final pair and owner checks, write only into separately authorized,
held, owner-private output disjoint from both roots and profile secrets.
Use bounded no-clobber artifact publication, read-back and the declared
file and directory barriers. Readers admit a complete authenticated
dependency closure. A conflict, failed barrier or uncertain output retains
the incumbent and any private artifacts for reconciliation. This decision
creates no mutation capability for either synchronized root.

## Preview and compatibility

Preview accepts either explicit no history or an exact authenticated seed
selected by digest. Invalid or unavailable history blocks that request.
Reobserve both current sides under the same scope and call the existing
classifier with the admitted evidence. Confirmed absence requires allowed
lookup and recheck on the same held root. Permission failures, disconnection,
change, unknown or incomplete observation block the selection. Different
files, one-sided edits and deletion conflicts stay visible. A one-sided
present file with confirmed absence on the other side can nominate a
create-new copy for separate approval. A preview and its inspection grant no
root effects and cannot create or advance a baseline.

Use the pack's separate typed workflow envelope and bounded immutable
references after registry review. Keep ordinary Plan and Manifest contracts
byte-compatible. The selected digest, trusted owner and record kind are
inputs to admission. Validate version, required features, signatures,
canonical encoding, declared lengths and counts, exact pair and dependency
closure before using historical or preview data. A child copy Plan would
require independent ordinary approval outside its parent. It could not
advance or reconcile the baseline. See [contract versioning](contract-versioning.md).

## Responsibilities

| Owner | Responsibility |
|---|---|
| Model | Keep the existing pure classifier and P-041 independent. Add only the pure predicates justified by the reviewed genesis contract. |
| Transfer engine | Bind the ordered scope, coordinate independent measurements and final pair recheck, admit authenticated history, project to the classifier, and order private artifact creation. |
| Linux platform and endpoint contracts | Supply held parent/child identity, scoped read-only observation, typed exact-absence evidence, bounded reads/rechecks and a distinct output capability. Never infer authority from persisted identities. |
| Manifest and Plan format owners | Own the baseline observation leaf and workflow root/plan representations respectively. Fix canonical encodings and bounds through contract review before parser or writer activation. |
| Application | Select the authorized pair, raw basename, owner profile, history digest and output namespace. Compose native capabilities and render blockers and omissions. |
| Root contract integration | Review the existing workflow registry and allocate only the fields and domains required by the selected profile. Record compatibility and affected obligations in the authoritative inventory. |

## Alternatives and consequences

- An implicit baseline on first equal scan reduces user choices but cannot
  identify the observational scope selected as history. Explicit genesis
  binds the expected pair and seed digest.
- Cache metadata can avoid re-reading large files, with a weaker claim.
  Strict genesis independently hashes both streams. It pays two full reads.
- Ordinary single-file manifests express one stream without paired metadata
  and evidence scope. Keeping genesis in a workflow record preserves
  existing single-file format semantics.
- Generation publication with an active pointer would need serialization,
  competing-writer and crash reconciliation. The first slice leaves
  selection explicit and immutable. Successor work requires a current
  predecessor, complete observations and completed verified action receipts
  before any advancement. Uncertain or partial outcomes preserve history.

## Acceptance and assurance

This slice addresses portions of R-269–272 and R-276–277 under INV-025/026.
Exercise divergent edits and equality (A-269), unavailable roots versus
confirmed absence (A-270), and same-size/same-time different bytes (A-276).
A-271 cache rebuilding, A-272 action crash reconciliation and A-277 actual
workflow approval remain later gates. Test digest and child substitution in
the preview parser without claiming apply coverage.

Require an independent bounded genesis model or reference oracle before
enabling the seed writer. Exercise both read orders, missing/mismatched or
reused evidence, a changed final observation and an output conflict. Keep
P-041 and its independent successor negatives at their existing bounds.
Verify canonical encodings with independent vectors and malformed input
controls, and immutable artifact output with native Linux failure fixtures.
A durability claim requires distinct process-crash evidence. Qualified
power-loss evidence remains separate. Exact acceptance cases and proposal
ownership inform implementation review. [Verification](../verification.md)

### Native ext4 platform evidence

At `bbc261e`, the hosted Linux x64 ext4 fixture executed its exact ignored
platform test under Rust 1.100.0. The raw transcript records one pass and
zero ignored cases. The lockfile, manifest, Cargo test target and selector
match the recorded source. The runner measured SHA-256 on the held test
executable and retained the digest and logs. It removed the executable with
the private build tree. Before and after observations matched the boot,
mount and namespace identities, and cleanup confirmed that the fixture
and private build were absent. [Native run](https://github.com/replicraft/ExaCopy/actions/runs/45906076231) · [Fixture manifest](../../crates/platform/exacopy-platform/verification/sync_history_ext4/fixture.toml)

The result covers held ordered roots and raw subject names, bounded named
member reads and exact EOF, and refusal after aliases, replacement and
root-order changes. The observed ext4 mount used `nobarrier` and
`data=writeback`. Durable publication, authenticated live preview admission,
managed ownership and cooperation, baseline creation, CLI activation and
sync mutation remain outside this result.
