# Transfer verification

The owning [ledger](obligations.toml) registers P-056's read-only retained
prefix comparison. The dispatcher runs ordinary package tests through
nextest. The workspace evidence recorder executes the exact registered
oracle and records its source, lockfile, command and transcript digests.

The oracle supplies real canonical signed journal inputs and deterministic
held-reader adapters. It compares all proposed bytes, checks historical
checkpoint digests, varies every source and local byte, and exercises
identity, epoch, size, scratch, failed-read and cancellation boundaries.
No result may escape after an incomplete comparison. Bytes beyond the
old writer's declared extent refuse even when the fresh bytes match.

The application independently binds the actual authenticated source and
route to the signed scope, and keeps the exact private-stage lease and
observation. The comparator supplies observation evidence and a fresh
hash state. It does not authorize writing, restore a closed writer,
establish source EOF/close, or confirm a durability barrier.

Same-file append remains disabled until the explicit continuation record,
native append capability, qualification campaign, finalizer and receipt
are integrated. See [the reuse contract](../../../../docs/architecture/remote-prefix-reuse.md).
