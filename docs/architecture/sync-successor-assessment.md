# Single-subject sync successor assessment

The pure `exacopy-model::sync_successor` guard assesses one explicitly approved
create-new action. This is a partial source slice of R-272 and INV-026. Its ten
synthetic regressions passed in the `8c1a311` hosted coverage run. The corrected
inventory passed at `b50ada3`: 97 model tests, 1,006/1,021 covered lines and
441/466 covered branches under the unchanged 95% and 90% minimums.
[Exact coverage run](https://github.com/replicraft/ExaCopy/actions/runs/46004576304).
It returns an advisory generation;
baseline persistence, pointer activation, native qualification, A-272 restart
reconciliation and P-028 publication barriers remain open.

The additional read-start interval guard and its regression have received source
review. Their execution result is pending; the historical coverage above does
not qualify the new guard.

Admission requires the exact independently authenticated current predecessor
and a representable successor generation. The observed durable intent must
match the complete parent approval, action, child plan and copy attempt. A
verified successful receipt must match that intent, the approved content and
required metadata, and the receipt association independently observed in the
durable journal. Source and published identities must differ.

Both complete measurements and final rechecks must bind the same ordered
roots, subject, evidence policy and scan. Each measurement carries its own start
position. Both reads must start after validation of the exact receipt and
complete after their respective starts. The final observations must still
match the measured identities and stability. Missing, stale, mismatched or
uncertain evidence requires reconciliation.

Approval, receipt and journal authenticity remain obligations of their
independent producers. The held-root inventory producer must truthfully report
the start position, EOF, required metadata and completion position of each full
read. The guard checks the supplied scan-local order. Native evidence must
establish that the producer actually performed and bound those reads.

A current-head snapshot can admit competing proposals. A future publisher must
compare the exact live head and activate its successor within one serialized
operation, revalidating the held postconditions at that boundary. This guard
exposes no writer, journal append, publication permit or CLI mutation.

See [baseline genesis](sync-baseline-genesis.md) and the
[immutable root contract](sync-baseline-root-contract.md) for the preceding
boundaries.
