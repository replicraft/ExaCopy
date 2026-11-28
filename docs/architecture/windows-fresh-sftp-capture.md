# Fresh Windows SFTP capture

The default-off `experimental-windows-sftp-capture` application SDK exposes
`capture_fresh_windows_sftp`. It composes an actual pinned SFTP source, one
nonrenewable grant, the original protected NTFS job and a separate signed
capture journal. There is no CLI selector, publication or restart entry.
Compilation, execution and native qualification of this slice remain pending.

The trusted embedding host independently selects the literal TCP peer, SSH
authority and account, host-key fingerprint, account-relative raw SFTP path,
maximum extent, original bootstrap and sibling identities, target, nonce and
exclusive process-monotonic deadline. The SDK confirms the actual held owner
against the canonical signed V1 bytes before network or credential acquisition.
It checks the peer of the exact stream consumed by SSH and the authenticated
SSH authority and fingerprint. There is no DNS retry, carrier substitution or
credential fallback in this entry.

The caller issues and claims one grant. It retains one mutex-protected
monotonic high-water and deadline; revocation and each admitted synchronous
native operation serialize through that same state. The grant is also checked
at socket polls. Native calls can block, so this provides no hard wall-time
or immediate transport-retirement guarantee. The embedding host owns the
underlying authority and any additional wall-clock policy.

The source is opened through `open_pending_source`. The actual observed extent,
attempt and epoch are checked before the real supervisor admits the binding.
That same held source is activated; it is not reopened. Full typed binding
equality includes the supervisor owner, not just its generation and epoch.
The caller must retain the independent selection receipt before any native
write. Its invocation commitment binds the complete selected scope and
connection under the separate grant hash domain. Reading an archived digest
cannot issue, renew or restore a grant.

The native pair retains the original V1 roles and an exclusively opened,
originally empty `capture-v1.exajnl` sibling. The guarded V1 append includes
its outer native barrier. The original bootstrap remains a 342-byte owner
and exactly one 310-byte framed segment followed by physical EOF. No capture
records are appended to that segment. Existing ancestry, owner, DACL, sharing,
stream and fixed-NTFS checks remain required.

The source, private stage and sibling remain within the lending native scope
while the unchanged `capture_live` engine runs. New stage identities are bound
once. Every bounded private write, prefix barrier, close and journal append
uses current admission. Stage readback also checks current grant state.
The engine independently measures the staged stream and confirms source EOF
and closure. Final native and route checks precede a successful values-only
report. Any refusal can leave private artifacts for inspection; it authorizes
no cleanup, rollback, publication or automatic retry.
The returned failure retains its typed cause, conservative mutation status and
last confirmed V1 and signed capture boundaries. Completed measurements survive
late failures; native closeout and route shutdown are confirmed separately.

| Record | Envelope kind | Signed payload bound |
| --- | --- | --- |
| Windows capture prepared | 43 | 778 bytes |
| Windows capture range | 44 | 180 bytes |

Both payloads use schema bytes `[1, 0]`, fixed-width little-endian integers,
strict Ed25519 signatures and distinct prepared/range domains. Preparation
binds the original signed owner and first-frame digest, original volume,
complete new role IDs, independently selected source and invocation,
connection generation, source epoch, observed extent and exact counted
UTF-16LE target. The original volume identity comes from the authenticated
V1 roles; all 128 file-ID bits are retained.

Every range binds the actual prepared digest, immediately preceding digest,
next ordinal, contiguous offset, exact length and supplied-byte BLAKE3 digest.
A prefix advances only after guarded append, full file synchronization and
bounded reread to the actual head and physical EOF on the same writer.
Archival inspection verifies the independent selection, each signature and
exact sequence, retaining only the last accepted boundary on failure.
Neither that summary nor a complete range count proves current native custody
or source closure.

The existing cadence remains 64 MiB with up to 4,096 range callbacks, including
a short final range and zero ranges for an empty source. Larger live streams
continue without adding callbacks after that count. With 92 bytes of envelope
per frame, the complete maximal history is
`(778 + 92) + 4096 * (180 + 92) = 1,114,982` bytes. The app statically requires
the native and storage caps to agree. Readers apply per-kind ceilings before
payload allocation and distinguish physical EOF from bounded exhaustion.

P-084 defines the independent signed-wire oracle. Source controls also cover
all range slots, torn successors, guard/refused readback behavior, full-width
supervisor substitution and native sibling identity, busy and nonempty cases.
These controls have not yet executed at the integrated revision. A separate
ignored integration target drives the actual SDK with a controlled real
SSH/SFTP peer and independently provisioned NTFS roles. It requires its own
trusted fixture inputs and qualified runner; the existing owned bootstrap
roster is unchanged. Positive execution and Windows SSH/WireGuard CLI
composition remain open. Same-boot and
mount continuity across independent restart, process-crash recovery and
power-loss durability remain unqualified.
