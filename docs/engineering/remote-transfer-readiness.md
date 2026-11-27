# Remote transfer release readiness

## Automatic read-timeout campaign

The direct commissioning workflow has a separate canonical-main matrix
case for an ordinary CLI invocation against stock OpenSSH authentication
and an isolated, bounded read-only SFTP fault helper. It withholds a data
READ after a 64 KiB stage prefix, observes the old connection closing,
and checks a newly authenticated source starting at offset zero into a
distinct empty held stage. The original stage inode and bytes remain pinned
through verified publication. Expiry, Ctrl-C, the original grant's total
retry bound, and wrong host-key refusal have separate cases.

The hosted run at `04b77c6` passed all five cases. Independent artifact
review matched the exact source, staged executable and repeated native
BLAKE3, all fifteen outer artifact hashes and all seven event/peer
transcript digests. [Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45867853948)

| Case | Observed result |
| --- | --- |
| Held READ timeout | Two authenticated sessions; the first closed after its read deadline, the second began at byte zero. The 192 KiB transfer published a distinct inode and receipt while retaining the original 64 KiB stage unchanged. |
| Grant expiry | One session, authorization refusal after 10.007 seconds, no publication. |
| Ctrl-C revocation | One session, cancellation after 0.127 seconds, no publication. |
| Original retry budget | Three sessions stopped after 52.012 seconds under the original grant, with no publication. |
| Wrong host key | One TCP connection, no accepted public-key authentication, authorization refusal. |

The parent requires every declared transcript digest before accepting
success. Cleanup uncertainty is bound to the retry job's own marker and
preserves partial evidence. The actual fixture was removed and owned
process groups were confirmed drained. Receipt bytes stayed in the
disposable fixture; its SHA-256 commitment is retained. This used synthetic
fixture authority. Embedded WireGuard, efficient prefix reuse, production
destination qualification and power-loss behavior remain separate.

The later [`caa573b` campaign](https://github.com/replicraft/ExaCopy/actions/runs/45871973178)
failed its budget-case attendance check: two sessions opened, held a READ,
and closed; the required third session never opened. All six authenticated
sessions across the preceding cases closed, and fixture cleanup completed.
That artifact did not export the budget invocation's terminal result or
elapsed time, so it does not establish why the third admission was absent.
The [`06212a3` campaign](https://github.com/replicraft/ExaCopy/actions/runs/45872972256)
then passed all five cases with the identical staged executable SHA-256
`9312340bf3d2a1ead3724fb3207a6cd6685983cda0854c439733af94cb642d37`.
Its three-session budget case stopped after 52.006 seconds with an
authorization refusal and no publication. The failed observation remains
unresolved; the passing repetition does not replace it. Subsequent fixture
diagnostics retain bounded terminal status before the unchanged attendance
and closure assertions.

The [`3861acc` campaign](https://github.com/replicraft/ExaCopy/actions/runs/45873691243)
passed all five cases with those diagnostics. Independent review verified
all five bounded terminal records and their hashes alongside the seven
peer transcripts. The budget invocation reported `E_AUTHORIZATION`, no
publication and 52.006 seconds, with all three held sessions closed.
Fixture removal and process-group drainage were confirmed.

The `56f7b84` budget case returned `E_IO` after 41.253 seconds with no
publication. Its SFTP log records two authenticated sessions whose held
READs each lasted about 20 seconds before transport closure. No third
connection opened. The retained report leaves the CLI's internal timing
unobserved. [Failed hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45920923086)

The `896552b` repair handles a direct socket closing during either of the
two checks that follow a held READ deadline. It rechecks the original
grant and connection binding, waits for the exact old route to retire,
and requires the existing retained-stage evidence before retrying.
Deterministic controls reproduced the closed-socket refusal with the
previous check and passed with the repair.

The `99fdf66` READ-timeout campaign passed all five cases on Ubuntu 24.04,
Linux `7.0.0-1018-aws`, and a whole ext4 root. The budget case opened and
closed three authenticated sessions. Each started at byte zero. The first
two held READs ended at their data deadlines. The third stopped when the
original 52-second grant expired. The CLI returned `E_AUTHORIZATION` at
52.005 seconds without publication. The fixture rechecked the identity and
bytes of the original 64 KiB stage. The redial case also published verified
bytes to a distinct inode and retained its old stage. The report confirms
fixture removal and process-group drainage. [Passing hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45924705323)

## Independent kernel WireGuard campaign

The commissioning harness can run the unchanged embedded BoringTun CLI
against a Linux kernel WireGuard peer and stock OpenSSH in two owned network
namespaces. The client has no kernel route to the inner SSH address. The
kernel peer's UDP socket remains in its birth namespace when its interface
moves, so the embedded userspace route must carry the traffic. Per-case
kernel counters, OpenSSH logs and a carrier-down refusal supplement the
ordinary byte and receipt checks. A passing report requires all bounded
carrier-down and retained-namespace evidence, plus confirmed fixture cleanup.

The manual provider-A workflow requires a positively observed existing
kernel provider. A separate canonical-main provider-B workflow can load
only fixed, hash-pinned module closures on a disposable hosted VM. It admits
the reviewed Azure 1017, Azure 1020, AWS 1014 or AWS 1018 boot after package,
ABI, dependency and same-boot checks. The AWS pins came from installed
provider observations and the independently authenticated Canonical Noble
security archive. The AWS 1018 read-only enrollment also established the
exact native dependency order. [AWS 1014 observation](https://github.com/replicraft/ExaCopy/actions/runs/45879217518) · [AWS 1018 enrollment](https://github.com/replicraft/ExaCopy/actions/runs/45905581642)

After an initial AWS 1014 boot-image ownership timeout, the hosted
provider-B dispatch can time one read-only search of the same path for up to
30 seconds. It discards the output and records the initial timeout, probe
duration and a fresh same-boot observation. The fresh ownership and installed
package queries each retain their five-second bound. This measures dispatch
after possible filesystem cache priming. The original first-query timeout
remains visible. Unconfirmed subprocess exit, boot drift or a changed source
checkout stops admission.

Other kernels, missing tools, drift or uncertainty remain blocked. Previously live
dependencies have name-only attribution; they do not inherit archive-byte
provenance. The runner VM owns loaded module lifetime.

The `99fdf66` provider-B run admitted the pinned module set on AWS
Linux `7.0.0-1014-aws`. Two qualification controls and the positive
download passed. The incumbent command refused the occupied target and
made no SSH connection. The kernel observer then refused the late peer
delta, with TX increasing from 4,780 to 4,940 bytes while RX, endpoint and
handshake stayed unchanged. No later cases or carrier-down ran. The run
confirmed client drain and fixture and marker removal.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45924705292)

The `b82e95d` provider-B run on Azure Linux `7.0.0-1020-azure` recorded
the two initial qualification controls. Its positive `get` reached
independent OpenSSH and passed the original kernel traffic check with
RX +3,490 and TX +4,780 bytes. In the settling window before the incumbent
case, TX increased by another 2,772 bytes, from 4,780 to 7,552, while RX
stayed at 3,490 and the endpoint and handshake stayed unchanged. The
observer did not record the required 22 continuous quiet seconds in
60.061 seconds. It withheld the `get` acknowledgment, leaving both the
incumbent and carrier-down commands unexecuted.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45928809368) ·
[Provider and campaign reports](https://github.com/replicraft/ExaCopy/actions/runs/45928809368/artifacts/15167269338)

The retained OpenSSH `get` transcript ends at SFTP session start. The
reports leave the origin of the later TX increments undetermined. The
Azure run confirmed client drain and fixture and marker removal. All
14 outer report commitments verified. Both native runs used synthetic
authority. Complete embedded commissioning, including the remaining
no-fallback and carrier-down controls, and production qualification
remain open.

The subsequent `bb6ebba` trace correlated the independent OpenSSH client
port 55822 with the kernel peer's `ESTAB` socket. Its send queue held
84 unacknowledged bytes; retransmissions increased from 3 to 4 and
retransmitted bytes from 252 to 336 while carrier TX increased by 160
bytes and RX stayed unchanged. This supplies direct TCP carryover evidence.
The last rejected sample was unavailable, so the early settling refusal's
exact cause remains unknown.
[Hosted trace](https://github.com/replicraft/ExaCopy/actions/runs/45930537107)

Successful ordinary embedded capture now requests a disconnect on the exact
authenticated SSH session before fencing the route. Its stream waits for
the owned TCP driver to drain queued bytes and complete FIN, peer EOF and
the closing phase. Enqueueing the SSH request alone supplies no completion
proof. A reset, revocation, cancellation or timeout refuses completion.
The wait is bounded by 32 seconds and the original grant deadline. The
application still fences and joins the original route, then rechecks its
generation and authority before finalization. Failed and interrupted
captures retain their previous hard-fence behavior. The `09b96f5` and
`993668d` hosted runs independently observed clean disconnects for both
ordinary get and fresh resume.

At `993668d`, the fixture also removed the exact socket left by deliberate
SIGKILL: client port 56902, kernel cookie 8193. A native cookie-bound
acknowledgment and subsequent empty TCP inventory confirmed the effect.
The distinct resume connection used port 58687 and disconnected cleanly.
Nevertheless, carrier TX rose another 1,332 bytes with RX unchanged, so
the observer failed its unchanged 22-second quiet requirement within
60.084 seconds. Packet types were not recorded. Post-intent and
carrier-down did not run; client and fixture cleanup were confirmed.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45940037149)

The next fixture revision performs that same exact-socket retirement at
the process-kill rendezvous, before fresh resume can start. Uncertain
retirement withholds resume. Fresh resume must still pass its independent
byte, receipt and disconnect checks, followed by the original quiet and
zero-connection checks. Portable controls passed; this revised ordering
requires native execution. Full commissioning and production qualification
remain open.

The observer also accepts iproute2's documented empty timer duration at
zero milliseconds and retains a bounded sampling phase on refusal. The
missing rejected sample prevents attributing the `bb6ebba` early refusal
to that parser defect. Exact TCP drainage and zero-traffic checks remain
required.

## Hosted direct OpenSSH commissioning

The ordinary main-push commissioning run at `69aecff` passed all seven
cases with the compiled `experimental-ssh-capture` CLI on Ubuntu 24.04,
Linux `7.0.0-1017-azure`, and a whole ext4 root. The independently
implemented OpenSSH peer listened on loopback. [Commissioning run](https://github.com/replicraft/ExaCopy/actions/runs/45824720986)

| Hosted case | Observed result | SSH connections |
| --- | --- | ---: |
| Qualification path control | The signed fixture record admitted the selected path. The occupied destination was refused before dialing. | 0 |
| Qualification signature refusal | Changing the signature on that same fixture path produced an authorization refusal. | 0 |
| Empty download | The CLI published an empty file and the harness verified its bytes and committed receipt. | 1 |
| Incumbent preservation | The CLI refused the occupied name and preserved its identity and bytes. | 0 |
| Capture interrupted by `SIGKILL` | The harness observed a 64 KiB partial stage. The target and receipt remained absent. | 1 |
| Pre-intent recovery | The CLI opened a fresh authenticated connection and read the full 128 MiB again from byte zero. The harness verified final bytes and the committed receipt and confirmed the prior partial stage was unchanged. | 1 |
| Post-intent reconciliation | Recovery reported confirmed publication and required reconciliation. The target, journal and receipt stayed unchanged. | 0 |

Independent artifact review matched the revision, source tree, lockfile,
harness hashes and staged executable digest, and checked all seven raw peer
logs. The two successful publications exercised the explicit data-only
omission profile and observed file and directory barriers. The artifact
retains receipt and journal SHA-256 commitments. Their raw contents and
payload bytes stayed in the disposable fixture. Its report records that
the fixture was removed and owned process groups drained.

The campaign used a synthetic, one-use fixture authority with assumed
qualification claims. Production destination qualification, power-loss
durability, independent embedded WireGuard commissioning and efficient
verified range reuse remain open.

The `99fdf66` hosted run also passed all seven ordinary cases on Ubuntu
24.04 and Linux `7.0.0-1018-aws` with a whole ext4 root. Both direct jobs
recorded the same staged executable digest. The ordinary job retained seven
OpenSSH case logs and confirmed fixture removal and process-group drainage.
The qualification record was specific to that synthetic fixture.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45924705323)

The `b82e95d` hosted execution passed all seven ordinary cases on Azure
Linux `7.0.0-1020-azure` and all five READ-timeout cases on AWS Linux
`7.0.0-1014-aws`, both on whole ext4. Both jobs used the held executable
with SHA-256
`458d7c8019d1ba2211bec64ecc19b8353334c9b753fc097fa3483dbe46ef77d5`.
The three retry-budget sessions each recorded an open, a held READ and
transport closure. The CLI refused publication at 52.006 seconds with
exit 8 and `E_AUTHORIZATION`. Both report file maps and all 12 exported
case transcripts verified. Both fixtures confirmed process-group drain
and removal. The results apply to the synthetic fixture authority.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45928809198) ·
[Ordinary report](https://github.com/replicraft/ExaCopy/actions/runs/45928809198/artifacts/15167324370) ·
[READ-timeout report](https://github.com/replicraft/ExaCopy/actions/runs/45928809198/artifacts/15167453997)

## Earlier native destination evidence

The ordinary main-push campaign at `d59f508` completed its unsigned hosted
Linux destination diagnostic. The retained artifact passed an independent
archive/digest review. The native fixture exercised four real process-kill
cuts: private creation, synchronized data, closed read-back, and publication
with directory synchronization. It ran on a whole ext4 root with
`nobarrier,data=writeback`; this is process-crash evidence, not power-loss
qualification. [Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45800002692)

That campaign used a small destination-only fixture. It did not transfer
over SSH or WireGuard, sign a production qualification, or qualify a later
deployment. Both native facts and substrate results explicitly set
`qualifies_remote_download` to false. The artifact records runner-measured
executable hashes but does not contain the executable for independent
rehashing. The later hosted direct campaign exercised the compiled CLI.

## Earlier integrated command review

Status reviewed on 2026-11-26 at `c8e3bd0`. The Linux source-build CLI provides
`get` and `recover remote-resume` with opt-in features. The direct build uses
`experimental-ssh-capture`. The `experimental-ssh-wireguard` build adds the
embedded route. The default CLI and official release build exclude both
features. The integrated revision passed its 30 declared proof gates and
881 macOS workspace tests with 25 skips. The later hosted direct campaign
adds Linux CLI evidence on the disposable profile described above. See the
[CLI command and profile reference](../../apps/exacopy-cli/README.md#experimental-ssh-download-on-linux).

Earlier integration through `8503dd3` on the same date: the generic finalizer
now requires a clean full-lifecycle capture replay, matching qualification
and exact native stage location before metadata effects. It accepts a fresh
capture after recorded retirement; journal and transfer tests passed 304
cases for that integration. The Linux publication bridge requires the final
application grant guard across the exclusive rename. SSH sessions retain
their actual authenticated authority and host-key fingerprint. Distinct
signed owner profiles bind hostname authority to a concrete socket peer and
preserve explicitly selected absolute SFTP paths, with independent vectors.
Application command and transport assembly followed at later revisions.

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
| SFTP source | The experimental CLI composes a protected SSH profile, pinned host key, selected route and authenticated SFTP source. The hosted direct fixture exercised absolute paths with independent OpenSSH. | Repeat against an independently qualified deployment and exercise both path forms there. |
| Private capture | The hosted direct fixture exercised a process kill and a fresh attempt from byte zero, retaining the unpublished partial stage. | Verify efficient range reuse separately. |
| Remote journal | The hosted direct fixture observed receipt commits and refused a fresh attempt after recorded publication. | Exercise additional publication and receipt interruption boundaries on a qualified deployment. Recovery from post-intent uncertainty remains a separate operation. |
| WireGuard | The experimental CLI composes the pinned userspace WireGuard/TCP route, with no direct fallback. | Confirm the actual embedded route against an independent WireGuard peer and exercise revocation, loss and renewal. |
| Fidelity | The hosted direct fixture checked the explicit `sftp-data-only-v1` omission set, bytes, receipt and barrier observations. Success reported `published_with_omissions` and exited 11. | Confirm the same observations on qualified deployments. SFTP provides live byte observations with incomplete metadata fidelity. |
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

## Collect native evidence

Run `python3 -B .github/ci/remote_qualification_test.py -v` from the repository
root for the portable wrapper controls. The Engineering policy CI job runs
the same command.

The [Linux remote qualification workflow](../../.github/workflows/linux-remote-qualification.yml)
has three manually selected operations. It retains passing and blocked
records. These runs do not sign a qualification or alter the release matrix.

| Operation | Fixture and result |
| --- | --- |
| `hosted-substrate` | An ordinary Ubuntu 24.04 runner creates a dedicated destination under its runner temporary directory. The production observer probes exact native eligibility and the existing destination-only process-kill fixture checks four cuts if supported. A subtree, unsupported kernel or split procfs leaves a failing diagnostic. The disposable directory and its inode cannot serve as a later deployment scope. |
| `unsigned-request` | The approved native deployment supplies an empty owned destination which persists across review and execution. The producer records the exact root, boot, kernel and mount, and the build digest in the CLI's BLAKE3 domain. The destination-only fixture exercises disposable descendants, then repeats the exact observations. An assembled unsigned request remains incomplete and deliberately exits 77. The fixture's modeled permit supplies no application or route qualification. |
| `qualified-cli` | The approved deployment supplies an independently reviewed signed destination qualification and separate, locally protected trust policy for the selected route and running build. The compiled command drives a dedicated independent OpenSSH fixture over direct TCP or an independent WireGuard peer. The harness retains refusal, publication and interruption evidence, exact byte and receipt checks, and any failing outcomes. |

Ordinary push CI on `main` runs the same hosted diagnostic on Ubuntu 24.04.
It uses the committed source and locked dependencies. It needs no protected
deployment, secrets, signing key or attestation. Both entry points retain
the native result and propagate its status. An unsupported host is a blocked
diagnostic and leaves the check failing. The diagnostic claims only observed
destination eligibility and the destination-only process-kill cuts that
executed.

The launcher retains logs and structured diagnostics even on failure. It
records its private fixture parent before creating the temporary
destination. Cleanup removes the original directory only after the
wrapper's build target is gone and the directory is confirmed empty.
Interruption or unconfirmed cleanup preserves the marker and any held
fixture on the runner. CI attempts to upload the marker and diagnostic
logs when the runner can still execute the upload step. The build target
and fixture contents are outside the upload paths.

Configure the runner group `exacopy-remote-qualification` to admit only
this workflow on protected `main` before registering a runner with access
to private profiles. Restrict the corresponding environments
`remote-linux-unsigned-request-<route>` and
`remote-linux-qualified-cli-<route>` to that branch and require reviewers.
This runner-group restriction is configured in GitHub outside the
workflow. Confirm the runner cannot accept jobs from other workflows or
refs before exposing the protected inputs. The hosted diagnostic uses a
standard runner and tests eligibility directly.

Set the environment variable `EXACOPY_REMOTE_DEPLOYMENT` through the
respective GitHub environment variable of the same name. It names a
bounded, single-link mode-`0600` JSON file owned by the runner user.
Its exact `schema` is `exacopy-ci-remote-deployment-v1` and `route` is
`direct-pinned-tcp-v1` or `embedded-wireguard-tcp-v1`. An unsigned request
also requires `destination`. The qualified campaign requires
`destination`, `owner_profile`, `ssh_profile`, `qualification`, `trust`,
`source_small`, `source_interrupt` and `sshd_log`. All paths must be
absolute and canonical. The owner profile is a directory. The other
campaign inputs are files outside the dedicated destination. The small source is an empty regular file. The interrupt source
provides the multiwindow case. The runner needs the locked Rust/tool inputs
and `b3sum`. The qualified campaign also requires
`findmnt` and the dedicated fixture server’s connection log. Store
credentials and trust input files on the reviewed runner. The workflow
retains synthetic fixture outputs, raw diagnostics and evidence hashes
without uploading the selected authority files. The qualification still
has to match the current boot and mount, exact build and route when the
campaign starts. Preserve its retained job directories and any uncertain
objects in the dedicated fixture. Prepare a separately reviewed empty fixture
before repeating the full campaign.

Run in a pristine, exclusively used source checkout with the pinned local
dependencies and no additional Cargo configuration. The workflow creates a
fresh external build target, compiles the selected release-profile CLI
with locked offline dependencies, and records the exact command, compiled
features, source tree and lockfile, source pin checks and binary SHA-256.
Source observations bracket the build and each facts collection. The
native test holds the actual fixture parent while running the four cuts
under disposable descendants on the same mount and boot. The unsigned
request assembler checks that parent identity against the separate facts
capture. Manual facts-only captures measure an independently selected ELF
and cannot attest a build from the checkout.

The hosted probe has run as described above. Both deployed operations still
require their own actual runner execution.
Before advertising the complete operation, extend the qualified campaign to
cover these behaviors on each proposed native profile:

1. Transfer empty and multiwindow files within the current 128 MiB extent
   bound. Compare final bytes independently, preserve an incumbent
   destination and inspect the committed receipt.
2. Observe interruption during capture, the seal, publication and receipt
   commit. Verify clean pre-intent fresh restart and the post-intent
   reconciliation refusal while preserving uncertain or superseded objects.
3. Drop the network and revoke route generations. Check bounded failure,
   fresh authentication on an explicitly resumed attempt, and absence of
   direct fallback on the embedded route.
4. Exercise transport renewal, slow local read-back, rekey trust checks and
   cancellation with the actual owner.
5. Preserve exact command, revision, native fixture and failure evidence.
   Cross-compilation covers compilation. Native process interruption covers
   process-crash behavior under the observed profile. Power loss needs its
   own qualification.

Keep dependency suitability, whole-version Cargo Vet findings, native platform
qualification and production release evidence visible until resolved. A
version tag should describe the platforms and operations actually qualified.
