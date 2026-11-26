# Native Linux remote CLI campaign

This opt-in campaign covers the agentless read-only SSH/SFTP portions of
R-228/R-229 and the admitted embedded WireGuard route portions of
R-245/R-247–249. It exercises source and incumbent preservation, exact
read-back, pre-intent process interruption, recovery and refusal of a
second publication under INV-001–004, INV-006, INV-009, INV-014 and
INV-021/022. It runs the actual compiled Linux CLI. Tests for the Python
evidence oracles do not stand in for execution of the CLI.

## Fixture

Use an isolated native Linux runner on an eligible whole writable ext4
mount. Select an empty, owner-private destination directory. Qualification
must match that exact directory inode, boot, mount namespace, unique
mount, mount row, UID/GID, executable and route. A container's overlay
or a bind-mounted subtree is outside the selected profile.

Keep the task-owned sources, SSH profiles, known hosts and keys, owner
profile, qualification, trust, and evidence directory outside that
destination. Use only generated fixture data and independent fixture
credentials. Give the ordinary Linux command only its existing explicit
owner profile and protected SSH profile. The separate protected
qualification trust file must select an independent attestor and exact
campaign under the existing qualification codec.

Provision a dedicated OpenSSH daemon with a pinned Ed25519 host key,
a fixture account, an explicit literal listening address, and a
read-only SFTP subsystem. Use an owned mode-0600 unrotated daemon log
with raw OpenSSH `Connection from … on … port …` and
`Accepted publickey` or `Accepted password` lines, as produced by the
standalone daemon with `-E` and a verbose log level. Retain its version,
configuration scope, and fixture public identities separately. For
direct, listen on the profile's exact loopback endpoint. For embedded,
provide a separately owned WireGuard peer on the profile's loopback
UDP endpoint, with the daemon reachable on the exact inner listener.
The daemon must see the configured client inner IP. A kernel
WireGuard peer in an isolated, already provisioned runner network
namespace can supply the independent implementation. This script
does not provision the peer or change host networking.

Give the fixture account read access to the two local source paths
under exactly those absolute names in its SFTP namespace. Use distinct
regular, single-link files. The fixture selected by `--source-small`
must be empty. Use 8–128 MiB for the interrupted and resumed transfer. The source paths must remain
stable throughout the run. Choose a large enough file or a bounded
fixture peer workload that the process can be stopped during an actual
partial stage write. The runner has no fallback to a timed cut.

Use the compiled feature-selected binary from a clean source checkout,
`findmnt`, and an independent `b3sum` program. Execute one route per
attested destination and evidence directory.

```sh
python3 -B apps/exacopy-cli/verification/remote/campaign.py \
  --binary "$binary" --destination "$destination" --owner-profile "$owner_profile" \
  --ssh-profile "$ssh_profile" --qualification "$qualification" --trust "$trust" \
  --source-small "$source_small" --source-interrupt "$source_interrupt" \
  --sshd-log "$sshd_log" --route "$route" --evidence "$evidence"
```

Use `direct-pinned-tcp-v1` or `embedded-wireguard-tcp-v1` for
`route`. The evidence directory must be absent under an existing
owned parent. The script retains per-case reports, stderr, bounded peer
log slices, actual journals and committed receipts, and `summary.json`
with the exit status and artifact SHA-256 hashes. Each CLI output
stream is bounded. Group cleanup occurs before reaping the leader,
including when the leader has already exited. Before a nested CLI
group can start, the runner persists `cleanup-unconfirmed.json` in the
campaign evidence directory. It removes the marker after confirming
group termination, closure of inherited output descriptors, leader
reaping and absence of any remaining group members. The final check
is observation-only. A supervisor must preserve the fixture and compiled build
while the marker exists, even if the campaign was interrupted before
it could write its blocked summary. The selected protected
SSH profile, trust, qualification and binary stay held and are
rechecked across invocations.

1. Create an exclusive 0600 control entry beside the genuine signed
   record in its owner-private directory. Verify the original bytes
   on that exact inode are accepted far enough to detect the seeded
   incumbent. Flip only one signature byte. Require authorization
   refusal at the same path/inode with unchanged destination names and
   no observed OpenSSH connection.
2. Download the empty source and compare all independently read
   bytes and EOF. Verify the exact published mode, owner and receipt
   association, the reported qualification digest, and all omissions.
3. Supply an incumbent and verify conflict, exact unchanged bytes
   and identity, and no observed connection or new job.
4. Observe a real partial native stage. Request SIGSTOP for the owned
   CLI group and wait for the child group-stop event. Confirm the
   stage remains partial and the target and receipt are absent, then
   kill the group with SIGKILL. A missed cut is a failure.
5. Use `recover remote-resume` on that exact retained job and
   remeasure the published bytes and committed receipt. Preserve
   the earlier partial stage and its exact bytes and identity.
6. Reinvoke `recover remote-resume` on the now published job.
   Require recovery-required with historical publication, unchanged
   receipt, journal and final inode, and no observed OpenSSH connection.

The exit codes are 0 for measured campaign pass, 1 for a failed case
or observation, and 77 for missing eligibility or prerequisites. A
failed native campaign and the owner's output remain available for
review. The runner leaves owned files in the dedicated fixture
destination so that failure and recovery evidence can be inspected.
The fixture owner should remove its dedicated source, destination,
processes and credentials after collecting the necessary evidence.
Never upload production credentials, paths or logs as campaign evidence.

A pass covers one independently configured peer, one boot/mount
scope, and one selected CLI build. The process-kill case is at a
confirmed partial pre-publication stage. It does not exercise every
finalization crash boundary, physical power loss, or both route
classes in one invocation. No observed OpenSSH connection is scoped
to the dedicated fixture listener. For embedded WireGuard the
OpenSSH-side inner address and account observation leaves independent
outer packet or verified topology evidence as a separate requirement.

## Unsigned qualification antecedents

Use the native facts observer and the
[destination substrate diagnostic](../../../../tools/qualification/linux_remote_substrate.py)
on the same eligible runner. The diagnostic exercises actual native
process-kill cuts in disposable descendants through diagnostic model
authority. The facts observer measures the selected build and the exact
future CLI destination. The two artifacts have distinct scopes.

```sh
python3 -B apps/exacopy-cli/verification/remote/qualification_request.py \
  --binary "$binary" --build-manifest "$build_manifest" \
  --facts "$native_facts" --substrate "$substrate_evidence" \
  --route "$route" --evidence "$unsigned_request"
```

The assembler retains bounded source-matched facts, logs and hashes
and confirms the measured build independently. It requires the
locked-build wrapper manifest and raw build and pin verification
logs. It rejects a manually selected measured ELF, changed clean
source identities, or native substrate results without the exact
future destination parent, boot and mount association. An assembled request
exits 77 with status `incomplete`. Route-specific measured evidence
for the exact build and independent attestor review are still
required. The assembler emits no trust file, approval or signature.
The underlying contract is the
[qualification record](../../../../crates/storage/exacopy-journal/verification/remote_download/qualification.md).

Run the portable evidence-oracle controls from this directory with
`python3 -B -m unittest -v test_fixture test_process`.
