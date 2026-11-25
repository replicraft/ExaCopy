# Experimental BoringTun protocol backend

`exacopy-wireguard` uses exact BoringTun 0.7.1 for WireGuard handshakes,
authentication, encryption and replay handling. Its default feature set is
empty. `experimental-protocol` enables the backend; the ordinary CLI and
stable profiles do not depend on it. This is a packet library without a
socket, DNS resolver, interface or system route API.

A peer owns one approved outer address/port and one local/remote inner IP
pair. Caller-owned buffers bound inner packets to 1,420 bytes and encrypted
datagrams to 1,456 bytes. Only literal unicast addresses are admitted.
Configured static keys must be distinct and contributory. Application
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
no actual suspend/resume scenario was executed. The eventual actor must
recheck current generation and route authority before egress or delivery.

Session availability is a protocol observation, never proof of embedded
route confinement. Inner checks cover IP addresses and packet lengths;
TCP/UDP port, DNS-purpose and flow admission require the future stack and
actor. The [application route policy](remote-admission.md) remains separate.

Seven native macOS tests passed with real keyed two-peer IPv4/IPv6
exchanges, authentication/replay rejection, bounds, expiry, operation budget
and clock boundary checks. An independent raw BoringTun peer probe passed
in both directions at full MTU. Linux x86-64 feature-enabled checking also
compiled Ring C and assembly using Zig. Windows feature-off checking passed;
feature-enabled checking reached Ring and stopped at unavailable MSVC SDK
headers. These are distinct from native Linux/Windows execution.

The exact package archive matches the index/lock checksum and its packaged
upstream revision 051c9d47dc9c5cb36e461b7d36dcd673820dc98b. The
[upstream notice](../supply-chain/licenses/boringtun-0.7.1.md) is preserved
because the published package omits its license file. Narrow exact-version
license exceptions do not grant dependency audit criteria. Upstream
incoming ephemeral shared-secret validation, transitive whole-version
admission, kernel interoperability, sustained lifecycle and real egress
qualification remain open. No production support or tunnel availability is
claimed. Exact input hashes, raw failures and final results remain under
`/private/tmp/exacopy-boringtun-backend.qJjVePen` and the independent review
under `/private/tmp/exacopy-boringtun-review.Auk7zq0S`.
