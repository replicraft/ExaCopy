# Read-only public Plan export on Linux

The `plan SOURCE DESTINATION --profile PROFILE --output FILE` command
exports the public Plan v1 envelope and one PlanEntries leaf for a
preserve-mode `create_new` copy. The CLI owns the filesystem bundle writer.
The Linux engine supplies held native observations, the transfer planner
owns admission and measurement, and the codec owns canonical body and page
encoding. See the [CLI instructions](../../apps/exacopy-cli/README.md#export-a-plan-for-one-regular-file),
[public Plan JSON](public-plan-json.md), and [page format](public-plan-pages.md).

## Source and destination observations

The CLI opens the selected parents and an existing private owner profile.
It derives the logical root IDs from the selected profile's public key and
the held parent device and inode. The adapter refuses contradictory pairs of
logical root IDs and physical directories. Distinct source and destination
names can share a parent. The final names are exact raw Unix basename bytes.
The opened source is checked against the profile seed inode before metadata
admission and stream measurement. An alias of the seed is refused as well.

The planner checks destination absence before source measurement and again
at its end. It uses metadata-only observation for the target, including
symlinks. The source must satisfy the [Linux baseline metadata admission rules](../verified-staging.md#verified-private-stage).
The planner reads the selected held source, measures its logical BLAKE3-256
stream with bounded scratch, and rechecks the held inode, selected name,
metadata evidence and logical EOF. The command uses 256 KiB of streaming
scratch, which is the budget recorded in the body. The source observation is
`live_observed`; ordinary kernel reads may update atime. Export creates no
source or destination namespace entries and no copy job.

The export records one unnamed stream, the exact expected length and digest,
expected destination absence, a UUIDv7 Plan ID, and a bounded single-entry
scope. The source-view provider is `linux-local`, with no snapshot token or
stable-until time. The current command emits no expiry. It requests
`read-content` and `create-new`, sets `approval_required`, and leaves the
approval envelope absent. Its unsigned body digest binds the canonical Plan;
its page reference binds the separate canonical leaf. These records describe
observations and requested authority. Apply must establish live rights and
revalidate evidence separately. It remains unavailable in the CLI.

## Output protection

The explicit bundle parent must be an existing effective-user-owned `0700`
directory. The output-parent path refuses symlinks, magic links and `..`.
Its observed ancestry must be owned by the effective user or root, with
sticky protection on group- or other-writable directories. The bundle is
refused if it contains or is inside the selected source parent, destination
parent or profile directory. The check compares held physical directory identities
in both directions and uses bounded native mount observations. A known
whole-filesystem crossing is allowed. A mounted subtree or uncertain
ancestry is refused. The `pages` child must stay on the bundle mount and be
owner-private mode `0700`.

The bundle writer derives `pages/<lowercase-page-id>.exc` from the verified
DocumentRef. It creates the page and requested JSON output exclusively as
owner-only mode `0600` files, and refuses an existing plan filename. A
matching page can be reused after a bounded read verifies owner, link count,
identity and exact bytes. The writer synchronizes page data and the relevant
directories before creating the JSON. It then synchronizes the JSON and
bundle directory and rechecks scope and both names before printing the Plan
digest. Because JSON is written directly to the exclusively created file, the
name can be visible before its contents are complete. A failed or interrupted
export preserves incumbents and can retain incomplete artifacts. Readers
should wait for successful completion and verify both the envelope and page.

## Durability boundary

`minimum_durability = process_crash` records an apply prerequisite. It does
not change what the existing copy receipt claims, and completed export
barriers do not qualify copy publication durability.
`ProcessCrashEligibility` is a separate Linux platform check for matching
held roots against independently provisioned expected environment facts. It
uses the tested ARM64 Ubuntu/ext4 fixture profile, compares kernel, boot,
namespace and mount evidence, and checks that both roots use the same
eligible mount. That shared-mount constraint applies to this fixture, while
read-only export can cross known whole-filesystem mount boundaries.
The platform capability supplies no enrollment or qualification decision.
No current CLI or runtime call site uses it to admit an apply or promote a
receipt. See the [remaining apply bridge](public-plan-bridge.md).

## Retained evidence

The records below bind two private candidate source compositions, not a final
integrated native commit or a product qualification. Both ran with Rust
1.100.0 on ARM64 Linux. Neither exercised public apply or power loss.

- Six focused native Linux engine cases passed on ext4. They cover exact raw
  names and canonical body/page admission, alias consistency, occupied
  destinations, existing and dangling symlinks, byte-identical source
  rebinding, and an alias of a synthetic excluded seed. The source archive
  SHA-256 is `2b022e92f0b52cba441399af9fbd748f874f215ffe786c37df9327821b5c5176`.
  [Engine report](/private/tmp/exacopy-native-plan-tests.zwiquI/evidence/report.md) ·
  [Native log](/private/tmp/exacopy-native-plan-tests.zwiquI/evidence/native.log) ·
  [Input digests](/private/tmp/exacopy-native-plan-tests.zwiquI/evidence/input-archives.sha256)
- The CLI candidate passed 31 selected tests, strict affected-package Clippy
  and formatting. The CLI process probe exported a non-UTF-8 source name,
  preserved the source and an incumbent output, and refused unsupported flags,
  overlapping bundle scope and the profile seed. A separate successful case
  exported from ext4 roots to tmpfs. The candidate archive SHA-256 is
  `f445c56b88b93ca3e0aa84af8d83bc78ce17b225d77baf31d3db8b1da933d866`.
  [CLI report](/private/tmp/exacopy-cli-plan.LCxxm2/README.md) ·
  [Native log](/private/tmp/exacopy-cli-plan.LCxxm2/guest-plan.log) ·
  [Evidence digests](/private/tmp/exacopy-cli-plan.LCxxm2/evidence.sha256)
