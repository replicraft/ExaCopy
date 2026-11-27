# Windows bootstrap storage history

This source slice implements the portable historical codec for R-039–041 and
R-044. It does not provide a Windows job holder, journal writer, CLI copy or
recovery operation. Compilation, tests and native qualification are pending.

The caller selects the profile, verification key, job and admitted container
root independently of the records. It supplies five observed role identities:
root, job directory, owner file, journal directory and first segment. Each
identity preserves the canonical lowercase GUID, full unsigned volume serial
and all 16 native file-ID bytes. The tuple requires one volume and distinct
nonzero file IDs. Identity values cannot reconstruct native authority.

| Encoding | Contract |
| --- | --- |
| Owner | Domain 5, signature prefix `ExaCopy/owner/windows-fixed-ntfs-bootstrap/v1` followed by NUL; canonical CBOR body 234 bytes and envelope 342 bytes. |
| Version | Major 1, minor 0, required mask 1. Bit 0 binds all five roles. Layout 1 fixes names and admits no other history. |
| Role tuple | Seven elements: GUID bytes, serial as eight little-endian bytes, then five file IDs in role order. Exactly 133 bytes. |
| Prepared payload | Seven-key canonical map binding version, domain, job, token, exact owner-envelope digest, layout and roles. Exactly 218 bytes. |
| First segment | Existing v1 frame, kind `JobPrepared`, sequence 1, zero predecessor; exactly 310 bytes. |

The owner-body keys are version, profile, job, token, key, layout and roles,
numbered 0–6. The prepared-body keys are version, domain, job, token, owner
digest, layout and roles, also 0–6. Both key copies must match the independently
selected canonical strong Ed25519 key. Strict signature verification and
canonical re-encoding are mandatory. Existing Linux and Darwin domains and
bytes are unchanged.

Layout 1 derives the 45-unit job component from `.exacopy-` and the lowercase
UUIDv7. It selects `owner.cbor`, `journal` and
`00000000000000000001.exajnl`, represented as counted UTF-16 without a terminator.
Record content supplies no path to resolve. The external provisioner observes
all original role identities before signing. The pure signer emits bytes only.

Inspection compares the first payload with the exact authenticated derivation,
then requires clean logical EOF with a zero-payload cap on the terminal read.
An extra frame, suffix or terminal error returns no accepted history. A failure
after the first valid frame may retain that first boundary for diagnostics;
the extra frame's head is never returned as a prefix.

The consumer must independently establish held roles, exact names, ACL and
mutation custody, bounded record lengths, physical EOF and final native
rechecks. It must provide a finite interruption budget for real I/O. A slice or
length limiter supplies only logical EOF. Neither accepted history nor signing
provides publication, append, resume or durability authority.

The portable integration target `tests/windows_bootstrap.rs` includes literal
field and bitwise CRC oracles, trust and full-width role counterexamples,
validly signed malformed owners, re-framed payload changes, byte cuts,
terminal I/O failure, extra frames and old-dialect isolation. P-079 and P-080
register specific trust-selection and terminal-boundary regressions. Native
Windows custody and physical EOF remain separate acceptance work.
