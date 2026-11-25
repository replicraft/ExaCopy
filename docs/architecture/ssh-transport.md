# Experimental SSH/SFTP transport

`exacopy-ssh` is a default-off library using exact Russh 0.65.4 and
Russh-SFTP 4.0.0. `experimental-ssh` enables it without adding a CLI command.
The caller supplies an owned async stream; this crate performs no DNS
lookup or direct socket connection. It does not launch local subprocesses.
A supported build runs with no installed `ssh`, `sshd`, `ssh-keygen` or
`ssh-agent`, including on Windows. An actual remote connection still needs
an SSH server offering the selected suite and SFTP subsystem. The caller
owns the route and connection generation.

The initial suite admits strict Curve25519 key exchange, an Ed25519 host
key, AES-256-GCM and no compression. A mandatory independently supplied
SHA-256 fingerprint and an authority-bound strict trust snapshot are checked before asking
the broker for one explicitly selected supplied password or Ed25519 key. Changed/revoked/unavailable trust,
certificates and unattended prompts are refused. The broker request binds
host, port, account and verified key. Only a confirmed SFTP subsystem is
opened. Setup tolerates at most eight channel-window adjustments before the
explicit subsystem Success reply, within the same connection deadline. Data,
failure, EOF, closure and excess controls refuse setup. This fixes the ordering
observed with Apple OpenSSH 9.7p1. All known peer-initiated channels are refused. Rekey currently
fences the connection and requires a new verified handshake.

Password ownership uses zeroizing buffers and the upstream password method.
This does not establish complete credential erasure: the exact upstream
library retains an unwiped serialization scratch allocation. Certificate,
agent, MFA, private-key-file parsing and protected trust-store acquisition remain separate
work; no ambient configuration or credential lookup is implemented here.

The snapshot parser bounds total input to 1 MiB and 4,096 lines, supports
multiple matching keys, canonical literal and OpenSSH v1 hashed host labels,
and rejects malformed or unsupported patterns, negation and CA records.
Acquisition/ownership errors become Unavailable, never an empty trusted file.
Bare and bracketed default-port hashes are checked. A valid opaque hashed
revocation blocks the exact offered key even when its original spelling is
not recoverable; this conservatively blocks key reuse at another authority.
Host-key fingerprints remain SHA-256 and the authentication suite is unchanged.
HMAC-SHA1 is
used only for OpenSSH hostname-label compatibility. Protected byte acquisition
is still caller-owned and unimplemented, so this is not an ambient OpenSSH
configuration importer. SSH-keygen differential fixtures document its supported
lexical subset and intentional stricter refusals.

SFTP v3 reads/listing preserve raw names and opaque handles. Selected response
shapes are checked before the upstream packet decoder: mandatory attribute
flags, known fields, unique VERSION extension names, bounded NAME count and
exact frame consumption. This closes permissive upstream parsing in the
selected profile. Frames are capped at 256 KiB; only one request is outstanding.
Listings allow at most 4,096 entries in 128 replies. Whole-file reads use
caller-owned buffers up to 4 MiB and requests up to 32 KiB, with a 4,096
request limit. `open_read` also supports incremental reads with caller-owned
1–32 KiB buffers, at most 128 MiB and 4,096 data requests plus the final EOF
probe. Its single 20-second deadline includes caller processing between reads.
Bytes remain provisional until EOF, held metadata, successful CLOSE and named
metadata checks complete; only then may the session be reused. Dropping an
unfinished reader or cancelling a started read fences it. This bounded
prototype does not yet provide positioned reads or resumable transfer jobs.
Connect and each operation have 20-second timeouts. Cancellation,
started-operation error or timeout fences the session rather than reusing an uncertain channel.
These conservative prototype limits do not implement the final scheduler.

File observations compare server-reported size, mode and second-resolution
mtime around read-only handle use. They do not establish a snapshot, stable
remote inode or universal symlink/root confinement. Required metadata fidelity,
remote staging, writes, exclusive publication and recovery are unimplemented.
SFTP extension advertisements confer no such authority.

Twenty-eight native macOS SSH tests passed, including exchanges with an in-memory
SSH/SFTP peer. They cover raw names, short reads, EOF refusal, host and
credential scope, missing subsystem, frame admission and unsolicited channels.
Linux x86-64 checking also compiled Ring's C/assembly using Zig. Windows
checking reached Ring and stopped at missing MSVC SDK headers. The opt-in unprivileged Apple OpenSSH 9.7p1 localhost fixture also passed
verified Ed25519 authentication, listing, stat and exact read-back. It creates
random temporary keys and a read-only internal SFTP session over an owned
connected socket pair, without global SSH changes. The original window-update
ordering failure is retained. This is one local server/configuration profile;
Dropbear, NAS, native Windows/Linux execution and route qualification remain
open. Exact source and retained failure logs are under
`/private/tmp/exacopy-ssh-with-wg.bnV8hX` and
`/private/tmp/exacopy-ssh-source-review.2XJjGl`. Snapshot and independent
revocation/nested-length evidence is retained in
`/private/tmp/exacopy-known-hosts.trvGbH/evidence-v2.md` and
`/private/tmp/exacopy-known-hosts-review.hNDQBTMD/review.md`.

Existing ordinary CLI and storage feature closures remain unchanged. The
combined backend inventory records unassessed transitive versions and Cargo
Vet gaps; exact SPDX exceptions do not grant deployment audits. No product
SSH support tier or production qualification is claimed.


The supplied-key API owns an upstream Ed25519 private key constructed from a
zeroizing seed. It never contacts an agent or falls back to a password after
key refusal. Key exchange remains fenced on a second KEX.

## Portability and independent server tests

The normal experimental tests supply an in-memory SSH/SFTP peer. They run
with the feature enabled in the native Ubuntu, macOS and Windows CI jobs, with
no local SSH installation needed. Native CI requires the Rust target and its
C toolchain to build the pinned Ring backend. The workspace policy checks that
the production adapter uses target-neutral Cargo dependencies and guards
direct process and ambient I/O references.

The separate ignored OpenSSH reference test runs a private daemon over a
connected socket. Its descriptor wiring is currently implemented for Linux
and macOS. Windows interoperability with an independent local server has
yet to be qualified. The fixture has no Windows OpenSSH installation or
service prerequisite for ordinary tests.

For the optional daemon test, use a disposable environment with a normal
unprivileged account and an available loopback socket. Supply these
test-only variables before running the test.

| Variable | Absolute path |
| --- | --- |
| `EXACOPY_TEST_OPENSSH_SSHD` | The reference server executable |
| `EXACOPY_TEST_OPENSSH_KEYGEN` | The key generator for synthetic Ed25519 keys |
| `EXACOPY_TEST_OPENSSH_ID` | The fixture account query tool supporting `-u` and `-un` |
| `EXACOPY_TEST_OPENSSH_ROOT` | A writable scratch directory with a literal ASCII path and no spaces or config metacharacters |
| `EXACOPY_TEST_OPENSSH_SYSTEM_CONFIG_DIR` | The selected daemon's system configuration directory, which must have no `sshrc` |

```sh
cargo test --locked -p exacopy-ssh --features experimental-ssh --test openssh -- --ignored --nocapture
```

The daemon receives an explicit temporary configuration and uses its in-process
read-only SFTP subsystem. The fixture creates ephemeral keys and files and
avoids system service changes. Missing tools or an unsuitable fixture profile
fail this opt-in check. Record the specific server build and OS when retaining
the result. Earlier Apple OpenSSH source and raw results are retained in
`/private/tmp/exacopy-ssh-key-auth.xUpRlk`, with an integrated root run at
`/private/tmp/exacopy-openssh-root-native.log`.
