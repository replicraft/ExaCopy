# Remote endpoint admission

The endpoint crate contains application policy components for SSH/SFTP and
embedded WireGuard. They perform no network operations and trust observations
from a future independently reviewed transport owner.

## SSH/SFTP

`ssh_sftp` bounds an explicit host, port and account. Host-key admission
requires configured trust or an independently supplied fingerprint; changed,
revoked and unavailable trust records refuse credentials even with a matching
pin. Credential requests bind the verified authority and key, and carry an
interaction policy the actual broker must enforce. Reconnects require fresh
checks bound to their actual connection. This module neither parses a trust
store nor authenticates a transport session.

The generic SFTP v3 assessment retains extension advertisements for diagnosis.
File sync, rename and hardlink advertisements confer no exclusive publication,
namespace durability or protected replacement authority. Live SSH/SFTP,
credential acquisition, raw-name decoding and remote filesystem qualification
remain separate work. Seven native policy tests passed; this is only a scoped
part of R-228/R-229, not their end-to-end acceptance result.

## Embedded WireGuard

`wireguard` binds a previously approved profile revision, actor and monotonic
generation to at most 256 literal unicast IP/port/purpose grants. Stream, UDP
DNS and TCP DNS grants are distinct. A permit is consumed once under a fresh
matching embedded-route observation. Disconnect or a failed reconnect blocks
use; direct, system-network and unavailable routes are refused. A later
generation cannot consume an earlier permit.

The connector must serialize actor transitions with immediate permit
consumption. These checks establish no packet routing, AllowedIPs, DNS,
cryptography or socket confinement result. Those belong to a separately
qualified embedded provider and adapter. Seven native route-policy tests
passed for the scoped R-245/R-247–249 boundary. Full acceptance remains open.

Private source hashes and raw verification logs remain in
`/private/tmp/exacopy-ssh-endpoint.6msJQo` and
`/private/tmp/exacopy-wireguard-route.ytTLLOFG`.
