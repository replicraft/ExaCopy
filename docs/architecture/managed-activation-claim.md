# Private managed activation claim

The journal crate defines a fixed private record for the proposed
[managed recreate issuer](signed-sync-recreate-execution.md). This is
occupancy data. It has no signature, live grant, writable handle or proof
that a file or directory barrier completed.

`encode_managed_activation_claim` accepts the full expected selection.
`match_managed_activation_claim` compares one exact slice with that
independent selection and returns a byte commitment. Neither function
creates a file, spends an activation or restores execution authority.

## Canonical bytes

Contract `linux-managed-activation-claim` version 1.0 uses exactly 496 bytes.
Magic is ASCII `EXMACT01`; required features are zero. Scalars are little
endian and UUIDs retain their full 16-byte representation. There is no
padding, optional extension or trailing suffix.

| Half-open bytes | Field |
| --- | --- |
| 0–8 | Magic |
| 8–10 | Major and minor, one byte each |
| 10–12 | Required features, u16 |
| 12–44 | Activation commitment |
| 44–76 | Host-selection commitment |
| 76–92 | Owner profile |
| 92–108 | Managed pair UUIDv7 |
| 108–116 | Current predecessor generation, u64 |
| 116–148 | Current predecessor Workflow Root digest |
| 148–180 | Reviewed parent digest |
| 180–212 | Granted executable parent digest |
| 212–228 | Sole action ID |
| 228–260 | Scoped grant reference |
| 260–292 | Approved public child Plan digest |
| 292–308 | Approved public child entry |
| 308–340 | Private child Plan digest |
| 340–356 | Child job UUIDv7 |
| 356–372 | Full private child entry |
| 372–380 | Child epoch, u64 |
| 380–412 | Opaque slot identity projection |
| 412–444 | Opaque segment identity projection |
| 444–452 | Prepared sequence, u64 |
| 452–484 | Prepared head digest |
| 484–492 | Prepared extent, u64 |
| 492–496 | CRC32C of bytes 0–492, u32 |

The external commitment is BLAKE3 derive-key with context
`ExaCopy Linux managed activation claim record v1` over all 496 bytes,
including the checksum. CRC32C detects accidental corruption; neither
algorithm authenticates the owner or supplied field meanings.

Matching checks length, magic, version, required features and checksum
before decoding fields. IDs and commitments must be nonzero. Only the
pair and child job require UUIDv7 bits. Reviewed and executable parents
must differ, as must the slot and segment projections. The prepared
sequence must allow two successors, and its extent must be between 92
bytes and 64 MiB inclusive. Actual replay, EOF and sufficient space for
the two concrete records are separate checks. An extent of 64 MiB is
structurally representable but cannot admit further appends.

The full private entry is retained. The ordinary one-entry executor uses
numeric model `EntryId(1)` and the full private entry as its stage token.
The codec performs no truncation, hashing or conversion between them.
It allocates no attacker-sized buffer and performs no file I/O.

## Integration boundary

The selected future issuer uses one fixed `activation.claim` beside an
independently provisioned action ledger. Any occupied marker fences fresh
admission, including invalid, partial or foreign bytes. A successful byte
match after reopening cannot establish an earlier acknowledgement or
reconstruct a live permit.

Native adoption still requires independently authenticated activation and
host selection, an authoritative current predecessor, disjoint held role
ancestries, exact original segment replay and a consuming one-use writer
handoff. The live spend must follow actual file and directory barriers
and exact same-held readback. Unknown outcomes require reconciliation.
The native issuer remains unimplemented.

The [read-only preparation SDK](managed-recreate-preparation.md) produces
detached host, scoped grant, executable parent and signed activation bytes.
It compares native role projections from the original held objects. Its
first profile requires the same canonical owner key and owner profile for
the managed review and ordinary child, with distinct approver and attestor
keys. These byte and custody checks supply no operational issuer, current
selector or qualification. The review-only action page stays unexecutable;
an in-memory `LocalApplyGrant` is separate from the serialized grant.
This claim's single profile field cannot establish child ownership, and
its opaque role fields cannot select or establish native objects.

No workflow kind or journal-frame discriminant is allocated by this
format. In particular, workflow kind 6 remains `SyncBaseline`.

## Evidence scope

P-086 selects the independent golden record and domain commitment test.
Four separate ordinary journal tests cover every truncated prefix,
trailing data, bad headers, semantic invalidities with recomputed CRC,
sequence and extent limits, all 21 independently selected fields and
swapped native-role projections. The fixed-data oracle is separate from
the production encoder. Compilation and execution require evidence from
the integrated revision.

These checks establish neither native spend nor baseline advancement.
The bounded P-085 ordering model, native issuer qualification, child
provenance after restart and P-028 baseline publication remain distinct.
