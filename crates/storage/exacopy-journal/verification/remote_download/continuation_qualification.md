# Linux retained remote append qualification V2

The V2 reader has a dedicated operation profile for verified retained
append under the Linux process-crash contract. It verifies separately
selected attestor trust and claims about an independently reviewed
campaign. The route remains a separate choice, direct pinned TCP or
embedded WireGuard TCP. Both route classes require their own evidence.
The existing V1 destination qualification keeps its exact wire and
verification behavior for ordinary fresh-stage capture.

## Exact wire and trust

The maximum complete record is 3,072 bytes. Its canonical CBOR map is
`{0: 2, 1: 1, 2: body_bstr, 3: attestor_key_bstr32, 4: signature_bstr64}`.
Version 2 uses the qualification attestor role 1. The signature input is
`ExaCopy/linux-remote-destination-qualification/v2` with terminating NUL
followed by canonical CBOR `[2, 1, body_bstr, attestor_key_bstr32]`.
The record digest uses BLAKE3 over
`ExaCopy/linux-remote-destination-qualification-record/v2` with terminating
NUL followed by the complete signed envelope. A V1 result cannot enter this
reader or become its typed digest.

The body is a canonical nine-field map with the six fields of the
[V1 record](qualification.md), including the unchanged 11 exact native
observation fields. Three additional fields follow.

| Key | Field | Admitted value |
| --- | --- | --- |
| 6 | Operation | 1, verified retained append v1 |
| 7 | Coverage profile | 1, retained append process-crash v1 |
| 8 | Complete required case mask | `0x0fff` |

The independent expected selection supplies the attestor identity and key,
ordinary job-owner key, exact build, route, campaign definition digest,
campaign evidence digest, operation, and coverage profile. Equal, weak or
noncanonical owner and attestor key encodings are refused. Record size and configured trust
are checked before decoding the envelope. Signature verification precedes
the claim body and its variable-field allocation. All unknown fields,
noncanonical forms, unknown profiles, or missing or extra case bits
are refused.

The historical verifier returns a typed digest plus verified claims.
Consumers compare the selected actual owner key, route and destination
with those claims. The current-use matcher additionally compares the
actual measured running build and exact freshly observed destination.
The application still owns the live source, authorization and exclusive
lease. Neither record nor projection creates a native capability, current
grant, journal acknowledgment, or mutation authority.

## Closed case registry

The case mask is the attestor's declaration about the complete independent
evidence identified by the signed campaign digest. A native campaign
producer must bind the selected build, route and exact destination
environment to each required case and independent byte, identity,
namespace and process-exit checks. A bit requires all the listed subcases.

| Bit | Required evidence |
| --- | --- |
| 0 | Stop the prior writer, authenticate fresh SFTP on the selected route, read every adopted byte independently from remote and held local views, and recompute each historical checkpoint plus the adopted BLAKE3 prefix. |
| 1 | Refuse same-length and same-mtime wrong remote bytes, changed or rebound local stage, corrupted historical digest, older epoch, and a physical retained extent exceeding the prior authorized extent or current source extent. Retain the old inode and bytes. |
| 2 | Refuse a live old writer, competing job lease, and an incumbent before continuation admission. Confirm that none authorizes a suffix write. |
| 3 | Kill the actual process after independent comparison and before the prefix file barrier. Reopen from durable records, independently read preserved bytes, and confirm that no live append permit is restored. |
| 4 | Kill after the actual full barrier on the unchanged held prefix and before kind 40. Check exact retained prefix bytes, same inode, absent target, and no suffix write or continuation authority. |
| 5 | Exercise torn kind 40, synchronization failure and unknown append. Confirm no authorized tail effect and retain the exact ambiguous material. |
| 6 | Kill after kind-40 sync and before independent exact read-back. On startup preserve recorded bytes and compare the last accepted head. No historical record restores a live writer, even if canonical and complete. |
| 7 | Start the first authorized write exactly at the adopted end. Exercise lower offset, hole and overrun refusal and process interruption at the first positive tail write. Independently verify unchanged adopted prefix, native identity and incumbent preservation. |
| 8 | Require checkpoint and closeout budget reservation before every tail write, including the first. Exercise budget refusal, lost or stale write result, failed data or journal barrier, and stale checkpoint completion. Coverage and latest head advance only after actual exact synced checkpoint read-back. Exercise expired/revoked grant, changed route generation, and lost exact lease around a pending effect. |
| 9 | Finish both a positive tail and a fully adopted file with an empty suffix. Observe actual same-held-source EOF and close and completed native writer closure. Independently verify the whole local stage before metadata and durable publication intent. |
| 10 | Exercise late no-clobber collision, lost or uncertain publication response, and process recovery at the publication boundary. Confirm retained incumbent and no second rename or automatic redial from post-intent state. |
| 11 | Exercise successful continued publication with both directory barriers, exact continuation-aware intent, kind-18 association and independent physical receipt. Confirm metadata and exact V2 record digest. |

Embedded mode additionally needs independently observed outer WireGuard
transport and exact authorized route throughout the success and fault
cases. An SFTP peer's observed inner address alone does not establish
that evidence. Grants and authorization checks stay separate from key
rotation. Case failures, skipped cases and missing topology evidence keep
the campaign unqualified. Existing V1 substrate facts, staged synthetic
records, and abstract model proofs establish their own limited results.
Qualification of actual native retained append and power loss require
separate evidence.

## History and live activation

An explicitly selected continuation-aware replay keeps the independently
expected V1 digest for any older qualification-bearing records. It retains
the exact verified V2 digest as a different expectation. Only the exact
accepted kind-40 transition establishes the continued lineage and V2
expectation for subsequent continuation-aware intent, durability and
receipt. This V2 reader does not change mixed-history replay.
Historical inspection can authenticate a selected signed V2 record
offline. Effect admission verifies the actual current image, held root,
boot, mount namespace, mounted filesystem, source, grant and writer lease.
A historical attestation does not authorize a reconnect or reuse of a
writer after failure.

A clean native candidate still needs an authorized exact-build, exact-route
campaign on an eligible, independently supplied Linux environment and a
separately reviewed attestation. The code has no production signing API.
There is no option to use a fixture key or substitute a V1 test to
bootstrap current required evidence.

## Independent vectors

From this crate run
`python3 -B verification/remote_download/continuation_qualification.py --openssl /path/to/openssl`.
The verifier tests use deterministic synthetic keys, an independent Python
CBOR encoder and OpenSSL Ed25519. These byte vectors exercise the parser,
trust, profile and mismatch controls. They do not qualify native effects
or attest a production campaign.
