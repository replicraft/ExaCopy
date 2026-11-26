# Remote transfer release readiness

Status reviewed on 2026-11-26 at `b19190d`. The resumable SSH-over-WireGuard
CLI is not enabled yet. A transport fixture or a decoded receipt does not
establish that this complete operation is ready for release.

Integration update through `8503dd3` on the same date: the generic finalizer
now requires a clean full-lifecycle capture replay, matching qualification
and exact native stage location before metadata effects. It accepts a fresh
capture after recorded retirement; journal and transfer tests passed 304
cases for that integration. The Linux publication bridge requires the final
application grant guard across the exclusive rename. SSH sessions retain
their actual authenticated authority and host-key fingerprint. Distinct
signed owner profiles bind hostname authority to a concrete socket peer and
preserve explicitly selected absolute SFTP paths, with independent vectors.
These components still require application command and transport assembly.

The release publisher now verifies and promotes the exact draft database ID
and checks that `latest` selects it. Ten mocked release controls passed; no
hosted release was published or qualified by those tests.

The follow-up at `ac9e045` shares the packager's 257 MiB archive limit while
retaining the 256 MiB raw executable limit; all 12 release controls passed.
The integrated Rust sources through `8503dd3` passed 804 macOS workspace
tests with 21 skips and workspace doc tests. Seven loopback tests initially
failed under sandbox restrictions; the unchanged suite passed with loopback
access. Workspace strict Linux cross-Clippy also passed. This run used the
local APFS checkout `987ce56de4d41cac349d139418407024ebf9296e`, whose mounted
crate has no diff against the pinned revision; it does not establish an
exact-source-pin reproduction of the entire dependency workspace.

| Area | Integrated behavior | Remaining acceptance |
| --- | --- | --- |
| SFTP source | An optional adapter owns one authenticated session and held read pass, checks connection generations, reads bounded positioned windows and confirms terminal observations, EOF and close. | Connect protected profile, credential and route admission to an actual CLI command. Confirm ordinary hostname and remote path behavior. |
| Private capture | The engine verifies a closed private stage independently and preserves prior stages on fresh restart. Allocation epochs are separate from the last physically bound stage. | Consume the native adapters in the product workflow and execute interruption tests there. Efficient range reuse is separate from a fresh full pass. |
| Remote journal | Signed scope and directory bootstrap precede allocations. Bounded replay checks capture and finalization history; receipt association requires its exact terminal commitment and clean EOF. | Complete writable native finalization, sealed pre-intent restart and post-intent reconciliation. Historical records alone provide no native authority. |
| WireGuard | The optional BoringTun adapter and bounded connected UDP actor are integrated with conservative session limits. | Integrate the reviewed inner TCP composition and renewal APIs, their exact source provenance, application route ownership and cancellation. |
| Fidelity | Strict metadata admission refuses ordinary SFTP. An explicit unnamed-stream policy records all omissions and a non-clean outcome. | Enforce the selection before every writable admission and return the exact status and omissions from the CLI. No source inode, snapshot or absent additional streams can be inferred from SFTP observations. |
| Distribution | Latest-release download, platform archive selection, SHA-256 verification, pinned publisher verification and owned launchers are implemented. | Execute hosted release jobs and native platform lifecycle qualification. Provision production signing and trust inputs. The Windows store currently accepts one release identity. |

An isolated macOS fixture transferred 5 MiB plus 19 bytes through positioned
SFTP reads against independent OpenSSH over paired userspace WireGuard/TCP
stacks. It did not exercise durable capture, publication or recovery. Both
tunnel endpoints shared the tunnel and TCP implementations; independent
WireGuard packet evidence is a separate result.

The reproduced `15e3c4e` snapshot, using the exact pinned APFS source, passed
739 native tests with 21 skips and all 21 gates declared at that revision.
Later source additions have their own tests and additional obligations.
That historical result does not qualify the newer integrated tip.

An existing Docker Desktop ARM64 environment supplied additional native
evidence: 887 baseline tests passed, three Plan tests refused its subtree
mount, and 16 tests were ignored. A separate whole-overlay Plan run passed
four tests with one ignored. The combined remote-adapter candidate passed
86 affected native tests. These were separately recorded source snapshots,
not a complete current-tip run. All five selected-stream publication cases
stopped before rename because the guarded procfs boot-ID observation crossed
Docker's `/proc/sys` mount (`EXDEV`). The whole-ext4 and original procfs
qualification requirements remain enforced; this environment did not qualify
publication, interruption recovery or power loss.

Before advertising the complete operation, verify the actual command against
an ordinary agentless SSH/SFTP server and its selected WireGuard route:

1. Transfer empty and multiwindow files, independently compare final bytes,
   preserve an incumbent destination, and inspect the committed receipt.
2. Interrupt capture, sealed pre-intent work, publication and receipt commit.
   Recover through the shipped command while preserving every uncertain or
   superseded object. Missing acknowledgements never authorize another rename.
3. Drop the network and revoke route generations. Verify bounded reconnect,
   fresh source admission and the absence of direct-route fallback.
4. Continue beyond transport renewal boundaries and through slow local
   read-back. Verify rekey trust checks and cancellation with the actual owner.
5. Execute each advertised native destination profile and its process-crash
   campaign. Cross-compilation does not qualify filesystem behavior; process
   interruption does not qualify power loss.

Keep dependency suitability, whole-version Cargo Vet findings, native platform
qualification and production release evidence visible until resolved. A
version tag should describe the platforms and operations actually qualified.

