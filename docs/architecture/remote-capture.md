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

Ordinary SFTP cannot establish the existing required-data metadata profile.
The engine's default metadata admission therefore refuses it before job or
stage allocation. An explicit `sftp-data-only-v1` selection admits one
unnamed logical stream and binds its versioned policy digest into the signed
scope. It excludes unenumerated additional streams as well as source mode,
ownership, timestamps, ACLs, xattrs, flags, link topology, sparse layout and
storage representation. Unknown additional streams are excluded content,
not evidence that no such content exists.

This selection still requires complete independent byte and EOF verification,
restrictive local metadata and separate publication qualification. Its receipt
must report the exact omissions and a non-clean outcome. The policy helper
does not itself enable a CLI option, establish native facts or authorize a
writable reopen; the caller checks the recorded policy against its current
selection before effects.

The separate `remote_resume` coordinator admits a fresh pass from a
matching authenticated scope and a clean pre-intent history with an absent
target. Restart uses the latest consumed allocation to check consecutive run
and strictly increasing source epochs. Every accepted allocation consumes its
epochs, including one left unbound after interruption. The last physically
bound stage is tracked separately for preservation and may be absent.

Under the exclusive job lease, the application first synchronizes a fresh
private filename allocation, then creates the stage exclusively and
synchronizes its namespace. It passes the fresh allocation's exact chain head
and epochs, and the preceding consumed allocation, into restart planning. A
replayed allocation without a recorded physical binding remains consumed, and
its name and any discovered material require inventory. Missing identity does
not establish absence or permission to adopt an orphan.

The journal adapter appends one stage-binding record as the immediate
successor of the fresh allocation. That record uses the allocated epochs and
the actual held stage identity. Capture cannot read or write before the
record's synchronization succeeds. An uncertain append requires reconciliation.
The adapter verifies the actual predecessor digest, record kind and bytes under
the lease. A returned sequence number alone supplies no durable evidence.

This restart path rereads the source from byte zero and preserves all earlier
stages. Efficient range reuse, qualified native publication and required
metadata remain separate. Tests cover interrupted allocation sequences,
exhaustion and head mismatches alongside the existing private capture protocol.
