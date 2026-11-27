# Experimental BoringTun protocol backend

`exacopy-wireguard` uses exact BoringTun 0.7.1 for WireGuard handshakes,
authentication, encryption and replay handling. Its default feature set is
empty. `experimental-protocol` enables the backend; the ordinary CLI and
stable profiles do not depend on it. The protocol module handles packets
in memory. The separate `experimental-udp` feature adds the connected-socket
actor.

A peer owns one approved outer address/port and one local/remote inner IP
pair. Caller-owned buffers bound inner packets to 1,420 bytes and encrypted
datagrams to 1,456 bytes. Only literal unicast addresses are admitted.
Configured static keys must be distinct and contributory. Incoming initiation
and response ephemerals are also checked through the existing X25519 library
with a fixed public probe scalar before BoringTun handles the unchanged packet.
At most 256 incoming handshake attempts per generation can perform that check.
Exhaustion blocks further handshakes while established transport can continue.
Application
payloads require an existing session and are not queued before handshake.
Transport counters at or beyond the protocol rejection threshold are
refused before entering the library. Every library action consumes one
of at most 2^20 operations per generation, including timer/control calls.

A generation expires after 120 seconds on the same clock used by the
selected library backend: Linux CLOCK_BOOTTIME, macOS CLOCK_MONOTONIC,
and Windows std Instant. Unix observations use the existing safe Rustix
API and checked conversions. Backward or unavailable observations refuse
operation. Clock and expiry checks run before library calls and before
exposing output. This closes the wrapper's earlier suspend-clock mismatch;
no actual suspend/resume scenario was executed.

Session availability is a protocol observation, never proof of embedded
route confinement. Inner checks cover IP addresses and packet lengths;
TCP/UDP port, DNS-purpose and flow admission require the future stack and
actor. The [application route policy](remote-admission.md) remains separate.

Eleven native macOS tests passed with real keyed two-peer IPv4/IPv6
exchanges, authentication/replay rejection, bounds, expiry, operation budget
and clock boundary checks. Low-order coordinates and their high-bit aliases
are refused in both handshake shapes; the independent peer probe also passed
with this guard. The scalar is public validation data, never a tunnel key. An independent raw BoringTun peer probe passed
in both directions at full MTU. Linux x86-64 feature-enabled checking also
compiled Ring C and assembly using Zig. Windows feature-off checking passed;
feature-enabled checking reached Ring and stopped at unavailable MSVC SDK
headers. These are distinct from native Linux/Windows execution.

The exact package archive matches the index/lock checksum and its packaged
upstream revision 051c9d47dc9c5cb36e461b7d36dcd673820dc98b. The
[upstream notice](../supply-chain/licenses/boringtun-0.7.1.md) is preserved
because the published package omits its license file. Narrow exact-version
license exceptions do not grant dependency audit criteria. The selected wrapper guards the identified counter and contributory input
paths. The original upstream API still lacks those checks for other consumers;
whole-version admission, kernel interoperability, sustained lifecycle and real
egress qualification remain open. No production support or tunnel availability is
claimed. Exact input hashes, raw failures and final results remain under
`/private/tmp/exacopy-boringtun-backend.qJjVePen` and the independent review
under `/private/tmp/exacopy-boringtun-review.Auk7zq0S`.

## Connected UDP actor

The actor takes exclusive ownership of one UDP socket already connected
to its approved literal peer. The caller supplies that socket and a
trusted route owner that serializes each observation with revocation
and replacement. Each generation can be claimed once. The actor checks
authority and its monotonic clock before processing, immediately before
nonblocking egress and before returning an authenticated inner packet.
The send boundary also compares the socket's connected peer with the
protocol output's destination. Backpressure drops that output. A single
receive waits up to one second and consumes at most one bounded datagram.

The first observed route loss, expiry, clock failure, exhausted operation
budget or socket failure retires the generation and closes its socket.
There is no DNS, system route management, inner socket or fallback path.
The endpoint dispatch handoff rechecks an opaque stream command against the
same generation and the peer's fixed inner address. The resulting target is
for future stack integration. An actual dial still needs authorization
at the initiating effect.

With the experimental UDP and TCP features enabled, Linux and macOS keep
FIFO-head control eligible while TCP ingress is occupied. The actor checks
the connected peer and a dedicated allowance before consuming a handshake,
cookie or empty transport candidate. Each admitted attempt spends one of
eight charges before dequeue or protocol work. Only a newly confirmed selected
key renews the allowance. The actor leaves ordinary protocol work in reserve,
and timers and write readiness remain independently eligible. A TCP data
datagram at the head stays queued and delays control behind it. Windows keeps
the ordinary receive-interest gating. The control path does not retain
ciphertext on native send backpressure.

The native tests use localhost and a synthetic route owner. They exercise
encrypted two-way traffic, peer and datagram bounds, revocation at egress
and during a receive wait, expiry, generation reuse, and dial admission.
They provide scoped evidence for R-239, R-240 and R-249 and invariants
INV-013 and INV-021–023. Kernel WireGuard interoperability, route-owner
integration, downstream packet admission and Windows native behavior
remain unqualified.
