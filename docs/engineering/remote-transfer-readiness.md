# Remote transfer release readiness

Status reviewed on 2026-11-26 at `c8e3bd0`. The Linux source-build CLI provides
`get` and `recover remote-resume` with opt-in features. The direct build uses
`experimental-ssh-capture`. The `experimental-ssh-wireguard` build adds the
embedded route. The default CLI and official release build exclude both
features. The integrated revision passed its 30 declared proof gates and
881 macOS workspace tests with 25 skips. Native Linux end-to-end acceptance
for either route remains open. See the [CLI command and profile reference](../../apps/exacopy-cli/README.md#experimental-ssh-download-on-linux).

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
| SFTP source | The experimental CLI composes a protected SSH profile, pinned host key, selected route and authenticated SFTP source. Selected relative and absolute server paths retain their exact bytes. | Exercise the compiled command against independent OpenSSH and compare the selected file bytes and final receipt. |
| Private capture | The native Linux command captures to a new private stage, seals and independently verifies it. Clean pre-intent history permits a newly authenticated attempt from byte zero while preserving superseded private material. | Observe actual process interruption and fresh-attempt recovery. Efficient range reuse is separate. |
| Remote journal | The native command signs scope, records allocation and capture, checks durable intent before exclusive publication and commits a receipt. Resume refuses another publish attempt when intent may have been recorded. | Exercise publication and receipt boundaries with a qualified native destination. Recovery from post-intent uncertainty remains a separate operation. |
| WireGuard | The experimental CLI composes the pinned userspace WireGuard/TCP route, with no direct fallback. | Confirm the actual embedded route against an independent WireGuard peer and exercise revocation, loss and renewal. |
| Fidelity | The CLI requires explicit `sftp-data-only-v1` before writes. Success with a committed receipt reports `published_with_omissions` and exits 11. | Confirm the exact omission set, bytes and durability observations in native results. SFTP does not establish source snapshot or inode identity, and the profile records incomplete metadata fidelity. |
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

The hosted probe and both deployed operations await actual runner execution.
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
