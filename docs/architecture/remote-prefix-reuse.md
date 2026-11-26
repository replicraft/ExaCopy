# Verified remote prefix reuse

This work addresses the checkpoint-evidence part of R-253/A-253 and R-255,
with INV-003/004, INV-009, INV-013, INV-019, INV-021 and INV-024. It does
not enable same-file continuation or automatic reconnect. Existing remote
jobs still start a fresh private attempt when resumed.

## Historical checkpoint inventory

The journal's opt-in finalization scan retains at most 4,096 checkpoint
declarations for the latest allocation. A new allocation clears those rows.
The ordinary scan retains its previous summaries without allocating a
checkpoint table. Both scans use the same canonical frame, signature,
context, epoch, predecessor, offset and lifecycle validation and byte budget.

An inventory is available only at clear EOF in a clean, physically prepared,
unsealed capture with at least one checkpoint. Any torn or corrupt suffix,
recorded uncertainty, or finalization phase blocks it. The inventory binds
the selected signed owner, scope, qualification digest, exact prepared and
checkpoint heads, private name, native identity declarations and epochs.
These are historical declarations. They establish no current file identity,
source snapshot, writer closure, durability barrier or mutation authority.

P-054 compares the old and opt-in readers across every checkpoint cut,
corrupts every byte of a checkpoint, exercises uncertainty and sealing,
and checks that a new allocation cannot inherit old rows. Diagnostics show
only the retained row count rather than dumping the whole digest table.

## Fresh verification before reuse

Ordinary SFTP provides no persistent file version or source inode. Size and
mtime do not justify skipping a remote prefix. An advanced reuse profile
must read each proposed byte from the freshly authenticated held source and
the exact held private stage, compare the bytes, and independently check
every historical checkpoint digest. It must accumulate a new whole-source
BLAKE3 state from those fresh bytes. In this profile reuse can save local
writes; it does not promise savings in network prefix traffic.

The initial strategy permits only a contiguous prefix, with bounded windows
and optional freshly compared uncheckpointed data under an explicit bound.
Incomplete reads, cancellation, stale epochs, changed identities or a
mismatch cannot return a usable partial proof or hash. Any fallback must
preserve the prior stage; a mismatch at one window establishes nothing about
later windows.

## Continuation remains a separate contract

The current private journal requires every StageAllocated record to name a
fresh file and rejects reuse of an earlier prepared inode. Keep those bytes
and interpretations unchanged. Before suffix writing can be enabled, add a
reviewed explicit continuation contract that binds the previous complete
history and checkpoint boundary, exact held stage, fresh run/source epochs,
new source observation and freshly verified adopted extent.

The native appender must retain the exact lease and held file across current
identity/name checks, the adopted-prefix data barrier and synchronized
continuation record. Its write capability must exclude the reused prefix.
Finalization and receipts must explicitly admit that continued preparation;
historical allocation frames cannot be fabricated into new authority.
Uncertain or post-intent history remains a reconciliation case. Reconnect
scheduling, deadlines, credentials and exact route retirement retain their
separate contracts.

The baseline recovery document defaults unversioned live sources to a fresh
attempt. The expanded connection-recovery contract permits fully revalidated
range reuse. Preserve the old profile and select advanced reuse explicitly
until the new journal, native appender, finalizer, receipt and fault campaign
are implemented and qualified together. This is not a relaxation of source
consistency or a size-based append mode.

## Explicit continued-history reader

The opt-in `replay_remote_continuation` scanner authenticates one first
kind-40 continuation from a clean, physically prepared original capture
with at least one accepted checkpoint. It separately selects the legacy
qualification, typed V2 retained-append attestation and immutable grant
digest. V2 evidence must match the actual selected owner key, route class
and recorded destination parent. Historical attestation facts remain
claims; they supply no current lease, grant or native admission.

The reader resolves the original allocation, preparation, bootstrap,
private name and nonce, recorded identities, epochs and old source extent
from the preceding history. It applies the 1,024-byte kind-40 payload cap
before reading or allocating. Continued checkpoints use the explicit
[1,0,15] required-version tuple; the old and new codecs mutually refuse.
The adopted aggregate over `[0, adopted_end)` remains separate from the
later suffix checkpoint rows. A historical range hash is not current
byte verification. A later append verifier must freshly reread both
regions, including the aggregate, before relying on them.

The first scanner supports continued capture, zero suffix and explicit
uncertainty. A further allocation, retirement, continuation or finalization
after kind 40 is refused pending its own explicit grammar. Unknown or torn
suffixes retain the accepted preceding boundary and require reconciliation.
Current commands still use fresh private capture from byte zero. The native
appender, continued finalizer and receipt, live qualification and interruption
campaign remain required before enabling prefix-preserving writes.
