# Private capture of a live source

The transfer engine's `capture_live` helper covers private staged data for
R-007, R-013, R-015 and R-018, with INV-001–004, INV-013, INV-021 and
INV-024. It consumes bytes from one held read pass into an already exclusive
fresh local stage. The caller owns the job, destination capabilities, source
epoch, cancellation and execution context for synchronous destination calls.

Every exact read is bounded by caller scratch and both endpoint limits. The
engine checks the source epoch before and after awaited operations and writes
only a completely accepted window. It hashes the supplied bytes and offers
each checkpoint only after the local prefix barrier returns the matching
stage binding. The fixed cadence is 64 MiB, with at most 4,096 checkpoint
records; subsequent bytes still undergo capture and final verification but
produce no additional progress records. This bound does not imply all bytes
have reusable checkpoint evidence.

Completion requires writer synchronization and closure, independent whole-stage
read-back with matching extent, digest and EOF observation, followed by source
EOF, final live observations and successful handle closure. A failed boundary
returns no completed capture. Private data and earlier records remain with
their owner for reconciliation. These observations do not establish a remote
inode identity or snapshot and cannot detect every concurrent source edit.

Deterministic tests exercise empty and short windows, stale epochs,
cancellation, prefix/checkpoint failures, checkpoint capacity, writer closure,
read-back corruption and terminal source refusal. Native metadata, durable
journal replay, efficient range reuse and exclusive publication require their
own adapters and admission. This helper does not enable a CLI command or
issue a publication permit.
