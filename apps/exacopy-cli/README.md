# ExaCopy command-line interface

Use `exacopy --version` or `exacopy -V` on Linux, macOS, or Windows.
The first line is `exacopy <version>` using the version of the running build.
The next line shows the current executable path as reported by the operating
system, escaped on one line, or `unknown` when unavailable. The operating
system may return a symlink path used to launch the command. Install origin
currently reports `unknown`. The command uses no local transfer profile and
exits 0 after successful output, or 2 if output fails.

The `exacopy` binary compares regular local files on Linux and in the opt-in managed APFS profile on macOS. Linux also supports creating and checking a portable content baseline for one regular file and planning or copying a regular file to a new name. The default output is human-readable. Exact byte comparison is the default and can be requested explicitly.

```sh
cargo run --locked -p exacopy-cli -- diff ./left ./right
cargo run --locked -p exacopy-cli -- diff /path/to/left /path/to/right --compare bytes --workers 4 --format json
```

The default comparison runs serially. Use `--workers N` after the two paths to set a ceiling from 1 through 16 for positioned reads. The comparator uses up to that many workers within the same 8 MiB scratch budget. All worker choices use the same byte relation, report format, and exit codes.

Each input may be absolute or relative to the current working directory. The command opens the named parent directory and selects its final filename as a raw byte component within that capability. It refuses trailing separators, reserved final components, final symlinks and non-regular files. Linux uses ordinary resolution of parent paths. A filename that matches a help flag can be passed after `diff --` or with a leading `./`.

| Exit | Outcome |
| --- | --- |
| 0 | Equal over all bytes of the two recorded extents |
| 1 | A difference in recorded length or byte content |
| 2 | Inconclusive, unsupported platform, invalid usage, or failed output |

The `exacopy.cli.diff` JSON summary has `schema_version` set to `1.0`, `relation` set to `bytes`, a `result` of `equal`, `different`, or `inconclusive`, and a `complete` Boolean for the relation decision. Successful decisions carry `consistency` set to `live_observed`. The lengths and offset are unsigned decimal strings. A first-byte offset is zero-based and establishes inequality. The summary reports a single witness. Inconclusive comparisons include an `error` with a stable code and an explanation. Invocation errors are written to stderr. Use `exacopy --help` for the command list and `exacopy diff --help` for the generated option reference. The paged diff report and shell completions are outside this initial command.

The command exercises the byte comparison and exit-status portions of the local CLI design. It has no persistent job, mutation, or publication authority. See the [diff crate](../../crates/engines/exacopy-diff/README.md) for evidence scope and source-observation limits.

### Managed APFS comparison on macOS

```sh
cargo run --locked -p exacopy-cli -- diff /path/to/managed-root/left /path/to/managed-root/right --managed-macos --workers 4 --format json
```

By passing `--managed-macos`, the non-root owner attests that each input parent path stably resolves to its exact independently provisioned, owner-private, materialized local APFS directory outside File Provider, on a volume with ownership enforcement. The paths must have protected ancestors in a trusted mount namespace, with no symlinks or possible redirection. Resolving either parent must require no automount or other filesystem trigger and no remote or File Provider lookup. The two inputs can share one parent.

Provision each parent with mode `0700` and an explicit empty extended ACL. Each selected file must be an owner-private, single-link regular file with mode `0600`. Processes outside the cooperating namespace must hold no access handles to the selected files, including handles obtained before provisioning. Every participating same-user process must hold an exclusive Darwin `flock` on the parent directory before changing it, its selected names or files, including through other handles or aliases. The adapter holds a shared advisory lock on each parent during comparison.

On macOS, omitting the flag returns `E_UNSUPPORTED_PLATFORM`. Using it outside macOS returns the same code. Successful comparisons use the standard report and exit codes and describe live observations. The CLI exposes managed APFS comparison. Managed APFS copy and recovery remain under library qualification.

The native CLI tests compile a small fixture provisioner with the Apple C compiler and use fresh owner-private directories in `/private/tmp` on local APFS.

```sh
cargo nextest run --locked -p exacopy-cli --test macos_diff
```

## Experimental local NTFS comparison on Windows

```powershell
cargo run --locked -p exacopy-cli --features experimental-windows-diff -- diff C:\synthetic\left C:\synthetic\right --local-ntfs --format json
```

Use literal absolute drive-letter paths in a trusted local Windows device
namespace. The command checks fixed NTFS volume roots, then opens each component
relative to its held parent. It refuses reparse points, drive aliases to subdirectories,
relative and UNC paths, device paths, alternate stream syntax, reported offline
or recall attributes, and inconsistent observations. Input names retain their
UTF-16 code units. Each path contains at most 64 components after its drive root.

Comparison reads the unnamed data stream and reports `live_observed` when it
can decide the byte relation. Mapped changes and filter-driver behavior may
escape live detection. Copy, recovery, metadata equivalence, named streams,
and snapshots are outside this profile. Windows qualification remains pending.
[NTFS fixture and evidence](../../docs/testing.md#windows-held-directory-ntfs-qualification)

## Preview one sync subject on Linux

```sh
exacopy sync-preview /absolute/common/parent LEFT_ROOT RIGHT_ROOT BASENAME --no-history
```

The root names must be distinct, direct directory children of the specified
parent. It must be on a whole local ext4, XFS or tmpfs mount with Linux
`openat2` and trusted procfs observations. Use a trusted mount namespace.
The command selects the same raw basename on both sides and refuses links
and mount crossings as traversal. It confirms each raw root or subject name
through a read-only directory scan bounded to 4,096 entries per check.
Lookup aliases and inconclusive scans block the preview. It measures at most
64 MiB per regular single-link file plus bounded one-byte EOF probes, and
never writes synchronized content or private history. Reads may update atime.

The JSON preview identifies observed absence, a measured file, or an existing
entry outside the selected file profile. An unavailable or unstable scope
blocks the entire preview. Present observations include the measured byte
length, BLAKE3 of the unnamed stream and a digest of ordinary mode, UID and
GID. Other metadata is outside the comparison. The report includes raw child
and subject names in hexadecimal and numeric identifiers for the held objects.
These identifiers describe only the live preview. Each held file is checked for
identity, length, change/modification times and required metadata around its
read and EOF probe. After both measurements the command rechecks the parent,
root bindings and selected names. These are live observations under the
stated kernel and filesystem contracts. Concurrent writers can change the
files between observations or immediately after the report.

Exit 0 reports matching live observations, both absent, or a possible
create-new copy for later review. Exit 3 reports a conflict. Exit 2 reports
a blocked preview or invalid invocation. Equal observations do not establish
trusted history, and a copy candidate grants no action. Independent roots,
subtree inventory and authenticated baseline selection remain open.

## Create and verify a single-file manifest

```sh
cargo run --locked -p exacopy-cli -- manifest create ./source > ./source.manifest.json
cargo run --locked -p exacopy-cli -- verify ./source --manifest ./source.manifest.json --format json
```

These commands run on Linux and require no private profile or copy job. `manifest create` writes a portable 1.0 JSON manifest to stdout. Choose a separate path for shell redirection. The manifest records the raw basename, the decimal byte length and the BLAKE3-256 digest of the file's logical bytes as a single unnamed stream. The observation is `live_observed` and the manifest explicitly omits metadata. The canonical body digest checks the manifest's integrity. Keep the unsigned baseline in a trusted location and select it explicitly for verification. Creating a baseline records the file's current observation and provides no evidence of its earlier state.

`verify` checks the selected baseline before opening the input. The input's raw basename must match the record exactly. The explicit input path selects the parent directory. The manifest's logical root ID and display annotations confer no path authority. Both commands use read-only input capabilities, though the operating system may update access times. Final symlinks and non-regular files are refused. A path starting with a dash can follow `manifest create --` or `verify --`. For verification, put `--manifest FILE` and any `--format` option after the input path. The public manifest and the private committed copy receipt serve different workflows.

Verification defaults to human output. The `exacopy.cli.verify` JSON report has `schema_version` set to `1.0` and a `result` of `verified`, `mismatch`, or `inconclusive`. Completed checks set `complete` to true and include the decimal length, algorithm, consistency, metadata status and unsigned baseline authentication status. A completed mismatch includes the expected and observed lengths or digests. Inconclusive reports set `complete` to false and include a stable error code. Invocation errors go to stderr.

| Exit | Outcome |
| --- | --- |
| 0 | Baseline created or file verified against the selected baseline |
| 2 | Invalid usage, input path, baseline, or basename scope |
| 3 | An input or baseline observation changed during the check |
| 4 | I/O, resource or output failure |
| 5 | Length or stream digest mismatch, or invalid manifest body digest |
| 6 | Unsupported platform, read capability, manifest version or required feature |

The current profile covers one regular file and a bounded unsigned JSON baseline. See the [independent manifest vectors and parser fuzz gate](../../crates/formats/exacopy-manifest/verification/manifest/README.md).

## Export a plan for one regular file

```sh
mkdir -m 700 ./plan-bundle
cargo run --locked -p exacopy-cli -- plan ./source-root/source ./destination-root/new-name --profile ./private-profile --output ./plan-bundle/plan.json
```

On Linux, `plan SOURCE DESTINATION --profile PROFILE --output FILE` reads
one regular source and checks that the selected destination name is absent.
Both parent directories must exist. The source and target are exact raw
final filename components. An occupied target, including a dangling symlink,
is a conflict. The source must meet the Linux basic metadata admission
rules. Reads may update access time. The command creates no destination entry
or copy job.

Select an existing [private owner profile](#copy-one-regular-file). The
profile is used to derive the plan's logical root IDs from the selected held
parents. The profile seed and its aliases are refused as source inputs. The
bundle directory must already exist, belong to the effective user, and have
mode `0700`. Use a protected, symlink-free path that neither contains nor is
inside the source parent, destination parent or profile directory. The CLI
refuses uncertain mount ancestry and aliases of mounted subtrees.

The requested output must be a new file with a basename other than `pages`.
The CLI writes an unsigned Plan v1
JSON envelope and a referenced canonical page at
`pages/<lowercase-page-id>.exc` relative to the bundle. Keep both files
together. Existing plan files are preserved. An existing page can be reused
after checking its owner-private file and exact bytes. New files have mode
`0600`. Wait for successful confirmation before reading the exported file.
An interrupted export can leave its newly created files incomplete, and the
CLI retains those files for inspection.

The command prints `Wrote public plan DIGEST` to stdout after the bundle
checks complete. Stderr carries diagnostics. The plan records a live source
measurement, expected destination absence and a requested minimum durability
of `process_crash`. The plan requires separate approval. Applying public
plans remains unavailable, and the export reports no copy durability result.

| Exit | Outcome |
| --- | --- |
| 0 | Plan bundle written and confirmation printed |
| 2 | Invalid usage or selection, unavailable input parent or profile, or forbidden source |
| 3 | Occupied destination or conflicting bundle entry |
| 4 | Planning, observation, I/O, encoding or confirmation output failure |
| 6 | Unsupported platform, unsafe output directory or uncertain bundle scope |

If confirmation output fails after the bundle was written, the CLI exits 4
and attempts to report that outcome on stderr. See the [read-only plan export
contract and evidence](../../docs/architecture/read-only-plan-export.md).

## Copy one regular file

```sh
cargo run --locked -p exacopy-cli -- profile init ./private-profile
cargo run --locked -p exacopy-cli -- copy ./source ./new-name --profile ./private-profile --format json
```

Create the profile once under a parent owned by your account or root. A parent writable by other accounts also needs the sticky bit. The CLI creates an owner-only directory (0700) with an owner-only Ed25519 seed file (0600). Keep the profile separate from data being transferred and select the same profile explicitly for later operations on the job. The path to the profile identifies the local authorization. The seed stays in the profile. The final profile and seed components must be regular directory and file entries respectively, with no symlinks and a single link to the seed. Restrictive creation masks or interrupted initialization can leave an incomplete profile for the caller to inspect.

The destination must be a previously absent name beneath a managed directory. An existing directory, dangling symlink, hard link, or file at that name is a conflict. The adapter refuses source symlinks and unsupported metadata. Source and target are selected as raw final filename components, with the same parent handling as `diff`. Use `copy --` when the source starts with a dash.

The CLI retains each started job in the destination parent under `.exacopy-<job-uuid>` with a signed owner record, a plan, a journal, and a committed receipt on success. A late failure may report the job name so its evidence can be inspected. The CLI leaves any private job material in place. The source is read-only and may have an access-time update.

The default text report identifies a successfully published copy and its committed receipt. `--format json` emits an `exacopy.cli.copy` 1.0 summary. The successful summary includes a UUIDv7 job ID, the job directory component, a decimal byte count, the BLAKE3 stream digest, and the committed receipt digest. The receipt represents a live-observed source, independent logical writes and buffered BLAKE3 read-back, and the adapter's basic metadata policy. Durability remains unconfirmed. Check [verified staging](../../docs/verified-staging.md) and the [Linux adapter](../../docs/local-adapter.md) for the metadata, barrier, and filesystem evidence limits.

| Exit | Outcome |
| --- | --- |
| 0 | Exclusive publication and committed receipt |
| 2 | Invalid usage or request |
| 3 | Conflict or stale plan |
| 4 | I/O, resource or report failure |
| 5 | Integrity failure |
| 6 | Unsupported platform, required capability or metadata |
| 8 | Profile authorization failed |
| 9 | Publication or its closeout evidence requires reconciliation |

A copy that reaches confirmed publication and then fails to finish its
journal or receipt can exit 9. The JSON report sets `publication` to
`published`, `result` to `failed`, and `pending` to `1`. When the
publication outcome still needs confirmation, the report uses
`publication_uncertain`. Use the reported job directory for recovery.
The publication field describes the observed outcome of the copy attempt.
The receipt appears only on a completed report. Durability remains
unconfirmed. This covers the local publication status portion of
R-009/A-009 and R-154/A-154 under INV-006 and INV-020.

If report output fails after publication, the CLI attempts to report the committed job on stderr and exits 4. The copy remains published. CLI process tests cover the report and authorization stringency, exact output content, authenticated job bindings, and exclusive publication under concurrency. These exercise the local portion of R-007–009, R-027–028, R-154 and R-194 and their corresponding acceptance cases. The development CLI and ext4 VM tests carry no release or power-loss qualification.

## Recover a retained copy

```sh
cargo run --locked -p exacopy-cli -- recover inspect ./destination/.exacopy-JOB_UUID --profile ./private-profile --format json
cargo run --locked -p exacopy-cli -- recover finish ./destination/.exacopy-JOB_UUID --profile ./private-profile --format json
cargo run --locked -p exacopy-cli -- recover resume ./destination/.exacopy-JOB_UUID --source-root ./source-parent --profile ./private-profile --format json
cargo run --locked -p exacopy-cli -- recover retry ./destination/.exacopy-JOB_UUID --source-root ./source-parent --profile ./private-profile --format json
```

Use the job name from the copy report and the profile that created it. The inspection takes a shared lease, authenticates the owner and plan, validates the accepted journal prefix and available receipt, and checks the current stage and target. A successful check is a current observation. The command is read-only and leaves the job artifacts available for further recovery.

Journaled copies can retain flush-backed measurements of partial ranges in the private job. Inspection checks the range pages referenced by the journal. A job interrupted during staging can report `retained_preparation`.

For `published_needs_barriers` or `published_needs_receipt` with a clean journal, `recover finish` takes an exclusive lease, authenticates the same evidence again, and freshly measures the published file. It records a new recovery generation, synchronizes the current publication and missing evidence, and commits the receipt. It reuses a valid existing receipt. Repeating a completed recovery returns the existing completion.

For `possible_retry` with a clean journal, `recover retry` takes an explicit grant for the original source directory. Supply the parent directory you selected when starting the copy. Recovery rereads the current source and retained stage, verifies required metadata, and records a new durable publication intent before an exclusive rename. It completes an already-published copy's receipt under the same lease. A mismatched source grant, identity, metadata, or stream returns `E_SOURCE_MISMATCH` or another integrity or I/O error, depending on the evidence that failed. Conflicts, torn journals, and missing prerequisites remain visible through inspection, with their evidence available for later recovery.

For a retained preparation with a clean journal and a bound private stage, `recover resume` takes an exclusive lease and an explicit grant for the original source directory. It checks each checkpoint against the current source and stage, then fills the remaining ranges. A full-length stage whose permissions were already applied can proceed after fresh full-file verification and metadata read-back. The source consistency remains `live_observed`. If the target is already published, recovery can finish its receipt. When the journal already holds an active publication intent and the stage is still private, the command reports the current disposition. Use `recover retry` for `possible_retry`. A conflict, torn journal, or unresolved evidence remains available for inspection.

The `exacopy.local_recovery_inspection` JSON schema version `1.0` includes the last accepted journal sequence and byte offset as decimal strings, whether the tail was clean or torn, and the disposition or blocking error. Exit `0` means the committed receipt and current target agree, `3` means an unrelated entry occupies the target, and `9` means the job still needs reconciliation or is in use. Exit `5` indicates invalid integrity evidence and `8` indicates that the supplied profile could not authenticate the job.

## Experimental SSH download on Linux

Build with `experimental-ssh-capture` to expose `get` and
`recover remote-resume` for direct SSH. The `experimental-ssh-wireguard`
feature includes that CLI and adds the embedded WireGuard route. Your
protected SSH profile selects the route. These commands are Linux-only
and default builds omit them. The unsigned
[v0.1.0-preview.2 Linux x64 archive](../../docs/releases/v0.1.0-preview.2.md)
contains both features and passed the direct and independent kernel
WireGuard campaigns using the same distributed ELF. Each deployment still
requires its own approved qualification. See
[remote transfer readiness](../../docs/engineering/remote-transfer-readiness.md).

Use paths to already provisioned authority files in the following examples.
The destination parent must be an admitted Linux directory and the final
name must be absent.

```sh
cargo run --locked -p exacopy-cli --features experimental-ssh-capture -- \
  get 'reader@files.example:/exports/report.bin' ./incoming/report.bin \
  --profile ./private-profile \
  --ssh-profile /path/to/private/ssh.json \
  --destination-qualification /path/to/private/destination.attestation \
  --qualification-trust /path/to/private/destination-trust.json \
  --metadata sftp-data-only-v1 --format json

cargo run --locked -p exacopy-cli --features experimental-ssh-capture -- \
  recover remote-resume ./incoming/.exacopy-JOB_UUID \
  --profile ./private-profile \
  --ssh-profile /path/to/private/ssh.json \
  --destination-qualification /path/to/private/destination.attestation \
  --qualification-trust /path/to/private/destination-trust.json \
  --metadata sftp-data-only-v1 --format json
```

Put the operands before the options. Supply the remote source as
`ACCOUNT@HOST:PATH`, with brackets around an IPv6 literal. The profile sets
the SSH port and must match the requested account and host. SFTP supports
both account-relative and absolute paths in the server's namespace. The
remote filename and local target retain their raw bytes on Linux. Empty
components, dot or dot-dot components, trailing separators and unsupported
non-regular sources are refused. The supported profile bounds the source
extent to at most 128 MiB and the foreground grant to at most one hour.

### Protected inputs and route selection

- `--profile` selects your [private local owner profile](#copy-one-regular-file).
  The local signing seed authenticates the job.
  Supply the same owner profile to resume.
- `--ssh-profile` selects a protected `exacopy-ssh-profile-v1` JSON file
  containing the host and account, port, independently approved Ed25519 host
  key pin, protected known-hosts path, one credential reference, one route,
  and the extent and grant bounds. The `password-env` method references an
  environment variable by name. The `openssh-ed25519` method references a
  protected key file and its public-key SHA-256 fingerprint. Encrypted keys
  require a named passphrase environment reference and bounded bcrypt
  parameters. The CLI checks the peer's host key before acquiring SSH
  credentials. Interactive prompts, SSH agents, ambient OpenSSH
  configuration and credential fallback are outside this profile.
- `--destination-qualification` selects a signed destination-only
  process-crash qualification for the actual destination. Supply
  the separate `exacopy-remote-qualification-trust-v1` JSON file through
  `--qualification-trust` to select the attestor identity and key, exact
  running build digest, route class, and campaign scope and evidence. Its
  `route` is `direct-pinned-tcp-v1` or `embedded-wireguard-tcp-v1`. The
  attestor key must differ from the local job owner key. The CLI verifies
  the artifact and current native facts before creating job or staging
  material. The native profile observes x86-64 or ARM64 Linux. The
  qualification binds the admitted writable whole ext4 destination,
  current kernel, boot and mount namespace. Missing, mismatched or stale
  evidence refuses transfer. Use the reviewed qualification artifacts
  for the selected deployment.

Run as an unprivileged user. The SSH profile, referenced known-hosts and key
files, and both qualification files require literal absolute paths on the
admitted ext4 or XFS filesystem mounted at `/`. Their ancestors must be owned
by root or the invoking user and exclude group and other writes. Each file
needs a directory owned by the invoking user with exact mode `0700` and a
single-link regular file of exact mode `0600` owned by that user. The reader
refuses symlinks, mount crossings and unstable observations.

A `direct` route uses the profile's fixed literal TCP endpoint. A
`resolve-authority` route uses the system resolver at initial `get` to select
one literal endpoint under the profile's address preference. The signed job
binds that exact endpoint, and resume reconnects only there. For embedded
WireGuard, build with `--features experimental-ssh-wireguard` and select the
`embedded-wireguard` profile route with its fixed peer, outer UDP endpoint,
inner SSH address and protected local key file. The file contains the
canonical WireGuard private key in standard Base64, optionally followed by
one LF. The local public key must match the profile. The embedded route has
no DNS lookup or direct fallback.

### Results, interruption and resume

`--metadata sftp-data-only-v1` is required. The operation copies the unnamed
data stream, verifies independent local BLAKE3 read-back, and uses mode
`0600` for the local file. The report lists omissions for additional streams
and resource forks, source permissions, owner and group, timestamps, ACLs,
extended attributes and security labels, file flags, hard links, sparse
layout, and compression or encryption representation. Source observations
are live. Snapshots and complete metadata fidelity are outside this profile.

Successful byte-zero publication includes a committed receipt and reports
`published_with_omissions` with exit 11. `--format json` selects the
`exacopy.cli.remote_download` 1.0 report. It includes the receipt and
qualification digests, exact stream length and BLAKE3, and the retained job
pathname with its original bytes in hex. It distinguishes observed file
and directory barriers from the required process-crash qualification.
Power-loss durability remains outside the profile. Human-readable output
is the default.

The default-off Linux `experimental-verified-prefix-resume` feature adds a
first witnessed continuation of a clean original capture. It requires explicit
retention consent and separately trusted continuation qualification. Witnessed
success uses `exacopy.cli.witnessed_remote_download` 1.1 and reports the committed
receipt and retained witness instead of claiming the ordinary full-stream BLAKE3
field. This path rereads the current remote prefix; it saves local staging work,
not prefix network traffic. Native qualification remains pending. See the
[first witnessed resume contract](../../docs/engineering/first-witnessed-resume.md)
for selection, authority and recovery limits. Follow the
[protected report capture procedure](../../docs/engineering/first-witnessed-resume.md#capture-a-protected-selection-report)
to retain the trusted invocation's complete JSON stdout separately from the job.
Witnessed success returns exit 11. Later `recover remote-inspect-witness`
inspection requires the
original qualified executable and current matching native facts, the protected
report, and both qualification/trust pairs. It loads no private owner key and
opens no SSH connection. A version 1.0 report lacks the required archive selection.

Select the reported retained job to resume. The command authenticates its
signed scope and checks the current authority again. Clean pre-intent
history can start a fresh attempt with a newly authenticated session,
reading from byte zero into a new private stage. Prior private attempts
remain available as evidence. Resume uses the recorded source, route and
destination. If a clean pre-intent job's target is already occupied, resume
returns `E_CONFLICT` with the retained job before opening a connection.
The exclusive writer still checks the destination again before any publish
attempt. Before connecting, resume also checks every recorded allocation's
private stage binding and extent, including superseded attempts, and refuses
an exhausted allocation or epoch limit. These checks retain the job for
reconciliation and do not authorize reuse of its old bytes. The shared read
lease holds the selected job through SSH authentication. Before the attempt
opens the source file, the exclusive writer rechecks the same job, owner
record and exact accepted journal boundary. A changed history requires
reconciliation. Once publication intent may have been recorded, recovery
remains a reconciliation case and the command refuses another publish
attempt. Retain the job when it reports uncertain or confirmed publication.

A current held SFTP data-read timeout can start another authenticated
attempt automatically after confirmed session retirement. The command
keeps the original finite grant and retry supervisor, releases the job
lease during backoff, and rechecks the exact retained files and journal
under a fresh lease before dialing. Each attempt starts at byte zero in a
distinct stage; prior bytes remain retained. Authentication, host-key and
route refusals, uncertain storage outcomes, and prior publication intent
stop automatic retries. A completed positive read on the current connection
can reset the backoff penalty after 30 seconds of verified connection health.
The reset retains the original grant expiry and refuses stale or revoked work.
A hosted direct-route campaign with synthetic
fixture authority verified timeout-to-redial, grant expiry, revocation,
the original retry budget and wrong-host-key refusal. Deployment
qualification and embedded-route acceptance remain separate. See the
[native evidence and limits](../../docs/engineering/remote-transfer-readiness.md#automatic-read-timeout-campaign).

Ctrl-C revokes the foreground grant and cancels the active session. A
confirmed cancellation can exit 10. Pending effects or uncertain evidence
can still require exit 9. The `publication` field may be `not_published`,
`publication_uncertain` or `published`, including when completed evidence
needs reconciliation. If writing the final report fails after publication,
the CLI attempts to report the retained receipt and job on stderr and exits
4.

| Exit | Outcome |
| --- | --- |
| 2 | Invalid arguments or selected configuration |
| 3 | Destination conflict |
| 4 | I/O or report output failure |
| 5 | Integrity failure |
| 6 | Unsupported operation or profile |
| 8 | Authorization refused |
| 9 | Retained state requires reconciliation |
| 10 | Cooperative cancellation |
| 11 | Published with a committed receipt and explicit metadata omissions |
