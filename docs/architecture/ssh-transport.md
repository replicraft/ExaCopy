# Experimental SSH/SFTP transport

`exacopy-ssh` is a default-off library using exact Russh 0.65.4 and
Russh-SFTP 4.0.0. `experimental-ssh` enables it without adding a CLI command.
The caller supplies an owned async stream; this crate performs no DNS
lookup, direct socket connection, proxy command, shell fallback or forwarding.
The future route owner must enforce its connection and generation policy.

The initial suite admits strict Curve25519 key exchange, an Ed25519 host
key, AES-256-GCM and no compression. A mandatory independently supplied
SHA-256 fingerprint and configured trust verdict are checked before asking
the broker for one supplied password. Changed/revoked/unavailable trust,
certificates and unattended prompts are refused. The broker request binds
host, port, account and verified key. Only a confirmed SFTP subsystem is
opened. All known peer-initiated channels are refused. Rekey currently
fences the connection and requires a new verified handshake.

Password ownership uses zeroizing buffers and the upstream password method.
This does not establish complete credential erasure: the exact upstream
library retains an unwiped serialization scratch allocation. Certificate,
agent, MFA, key-file and protected trust-store acquisition remain separate
work; no ambient configuration or credential lookup is implemented here.

SFTP v3 reads/listing preserve raw names and opaque handles. Selected response
shapes are checked before the upstream packet decoder: mandatory attribute
flags, known fields, unique VERSION extension names, bounded NAME count and
exact frame consumption. This closes permissive upstream parsing in the
selected profile. Frames are capped at 256 KiB; only one request is outstanding.
Listings allow at most 4,096 entries in 128 replies. Whole-file reads use
caller-owned buffers up to 4 MiB and requests up to 32 KiB, with a 4,096
request limit. Connect and each operation have 20-second timeouts. Cancellation,
error or timeout fences the session rather than reusing an uncertain channel.
These conservative prototype limits do not implement the final scheduler.

File observations compare server-reported size, mode and second-resolution
mtime around read-only handle use. They do not establish a snapshot, stable
remote inode or universal symlink/root confinement. Required metadata fidelity,
remote staging, writes, exclusive publication and recovery are unimplemented.
SFTP extension advertisements confer no such authority.

Twelve native macOS tests passed, including six exchanges with an in-memory
SSH/SFTP peer. They cover raw names, short reads, EOF refusal, host and
credential scope, missing subsystem, frame admission and unsolicited channels.
Linux x86-64 checking also compiled Ring's C/assembly using Zig. Windows
checking reached Ring and stopped at missing MSVC SDK headers. OpenSSH,
Dropbear, NAS, native Windows/Linux execution and route qualification remain
open. Exact source and retained failure logs are under
`/private/tmp/exacopy-ssh-with-wg.bnV8hX` and
`/private/tmp/exacopy-ssh-source-review.2XJjGl`.

Existing ordinary CLI and storage feature closures remain unchanged. The
combined backend inventory records unassessed transitive versions and Cargo
Vet gaps; exact SPDX exceptions do not grant deployment audits. No product
SSH support tier or production qualification is claimed.
