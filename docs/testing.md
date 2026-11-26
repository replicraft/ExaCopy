# Testing

Run the workspace commands from [README.md](../README.md) on the pinned Rust
toolchain. The [nextest profile](../.config/nextest.toml) records the workspace
configuration. Use a package selection for iteration and run the workspace
and affected platform and feature lanes before integrating. Run doctests
through Cargo.

| Test scope | Location and policy |
| --- | --- |
| Unit and integration | Keep unit tests with the owning module and integration tests in the owning crate's `tests/`. Cover supported behavior, explicit refusal, interruption and retained evidence. |
| Reference and fault injection | Keep reusable test support in the [engineering testkit](../crates/engineering/exacopy-testkit/). Use an independent expected result or model, exercise deliberate faults, and replay minimized failures deterministically. Run native failure tests on disposable synthetic files and record the actual filesystem profile. |
| Fuzzing | Follow the [Unix component corpus](../crates/foundation/exacopy-core/fuzz/README.md), [journal corpus](../crates/storage/exacopy-journal/fuzz/README.md), and [public manifest verification guide](../crates/formats/exacopy-manifest/verification/manifest/README.md). Keep targets and corpora crate-local. Include seeded accepted cases and malformed or adversarial inputs. |
| Benchmarks | Keep benchmarks with their crate. Measure verified operations under the same integrity and durability policies. |
| Formal checks | Follow the [verification guide](verification.md) and the owning crate's gate. |

The [feature matrix](../specs/features/matrix.json) defines supported
profiles and target restrictions. See [feature checks](../tools/feature_matrix.py)
for repeatable graph and build validation.

Substantial shared fixtures need provenance, a reproduction procedure,
expected properties and redistribution terms. Prefer deterministic generation
where that keeps inputs small. Freeze oracle expectations independently of
the production algorithm and include a negative control that demonstrates
the test can fail.

The [CI](../.github/workflows/ci.yml) and
[nightly assurance](../.github/workflows/nightly.yml) workflows define the
executed automation. Preserve raw outcomes and surface required jobs
that failed, timed out, were blocked or did not run.

The nightly public codec matrix fetches locked inputs and runs each parser's
ASan campaign with 250,000 inputs. The manifest JSON limit is 16,385 bytes;
the plan-entry page campaign uses 262,145 bytes, including an oversized seed.
It retains the revision and toolchain, lock and input digests, runner
metadata, raw output, corpus additions and any crash artifacts. A failed
or incomplete campaign fails the lane. These lanes exercise manifest JSON,
public document references and plan-entry page admission, leaving native
file verification to the Linux integration tests.
The canonical Plan body lane also exercises opaque extension admission,
including its 1 MiB body limit and a generated oversized input.

## Optional compiler cache

With sccache 0.18.0 installed, opt in to local development compilation from
the workspace root on macOS or Linux.

```sh
python3 -B tools/development/sccache.py -- build --locked --workspace
python3 -B tools/development/sccache.py -- check --locked -p exacopy-cli
```

Use `--binary /absolute/path/to/sccache` when the executable is outside
`PATH`. Each invocation owns a private Unix socket and server. The wrapper
uses a 1 GiB disk cache under `target/sccache/0.18.0`, excludes ambient
sccache settings, and disables Cargo incremental compilation for that
invocation. Only one session can open this cache at a time. sccache keys
account for the compiler, target, flags and dependency inputs. The wrapper
keeps normal path sensitivity. Cargo runs as the caller with its original
features and inputs.

In GitHub Actions, set repository variable `EXACOPY_SCCACHE=1` to opt the
Linux x86-64 native compile step into the checksum-pinned cache tool. Its
storage stays under the job's temporary directory. Native checks on the
other runners use their existing compiler path. Test, lint, formal
evidence and release commands run separately. A cache hit is a compile
optimization and provides no verification result. Continue to run the
checks documented above.

## Linux x86-64 cross-checks from macOS

Use official Rust 1.100.0 with its `x86_64-unknown-linux-gnu` target standard
library and the [pinned Pomologie source](../specs/dependencies/README.md).
Zig 0.17.1 has completed compile checks for this configuration. The optional
developer wrappers select Zig's Linux GNU C driver and archiver. They use
`zig` from PATH unless `EXACOPY_ZIG` names an executable explicitly.

Run from the repository root.

```sh
(
  set -eu
  exacopy_cross=$(mktemp -d)
  trap 'rm -rf "$exacopy_cross"' EXIT
  export ZIG_GLOBAL_CACHE_DIR="$exacopy_cross/zig-global"
  export ZIG_LOCAL_CACHE_DIR="$exacopy_cross/zig-local"
  export CARGO_TARGET_DIR="$exacopy_cross/target"
  export CC_x86_64_unknown_linux_gnu="$PWD/tools/development/zig-linux-x86_64-cc"
  export AR_x86_64_unknown_linux_gnu="$PWD/tools/development/zig-linux-x86_64-ar"

  rustup run 1.100.0 cargo check --locked --workspace \
    --target x86_64-unknown-linux-gnu --all-targets --all-features
  rustup run 1.100.0 cargo clippy --locked --workspace \
    --target x86_64-unknown-linux-gnu --all-targets --all-features -- -D warnings
)
```

These commands check compilation and lints for Linux. Runtime behavior and
release qualification use the native Linux workflows.

## Offline CLI installer fixtures

The [installer workflow](../.github/workflows/installers.yml) builds the
locked release-profile CLI with Rust 1.100.0 on Ubuntu x86-64, macOS arm64
and Windows x86-64. The POSIX job tests install and uninstall in a
disposable home. The Windows job checks the PowerShell parser, signed
artifact and refusal fixtures on the hosted runner. Unprivileged Windows
installation and uninstallation need separate lifecycle evidence.

The fixtures sign the newly built CLI with a disposable test certificate.
The workflow retains the commit, tree, lockfile and CLI hashes, platform
and verifier identities, and exit logs. A fixture failure also retains its
unsigned CLI input as workflow evidence. Test keys remain in the disposable
fixture directories. A distributable release has separate publishing gates.

## Windows held-directory NTFS qualification

The [hosted Read/Diff workflow](../.github/workflows/windows-ntfs-read-diff.yml)
selects separate jobs on canonical main pushes. It builds the pinned MSVC
test executables with the explicit candidate features and fingerprints
both the harness and the CLI exercised by the Diff tests. The fixture
checks actual fixed NTFS, the original held ancestor and scratch identities,
and the scratch's inherited trusted ownership and ACL. It makes no ACL or
ownership changes. Each declared selector must pass once, the reparse
controls are required, and cleanup must verify absence of the original
owned fixture. This profile qualifies only the executed controls under
the hosted runner's token and filesystem.

Read includes the existing held-directory candidate cases and a separate
production `WindowsReadFile` control. The latter confirms an equal result
first, then changes only a synthetic source timestamp through a distinct
attribute-only handle. The held comparison must report an inconclusive
left observation and preserve both byte streams. Diff invokes the actual
CLI for exact equal and differing bytes, raw-path refusals, file and
directory reparse refusals and an equal hard-link alias. The results make
only the live-observation claim.

The manual workflow's `Diff` mode exercises the opt-in CLI with absolute paths
on the verified NTFS fixture. It checks path refusal, equal bytes, first
difference, unequal lengths, worker selection, and preserved input bytes. The
optional symlink control exercises both the leaf and an ancestor. This is
separate from qualification of the held-directory by-ID candidate in `Read`
mode and the private staging capability in `Stage` mode. The CLI slice
covers R-007, R-016, R-058, R-059 and R-067 through their corresponding acceptance
cases, with the same live-observation boundary as the exact comparison engine.


The [manual Windows workflow](../.github/workflows/windows-ntfs-qualification.yml)
runs the `windows_read` integration test with the default-off
`windows-read-fixture` feature. The four parser tests are portable. Every
Windows filesystem test is ignored by the ordinary workspace test run,
including with `--all-features`. The manual workflow selects eleven tests
for the ordinary NTFS profile and requires all eleven to pass.

The same workflow's Stage selection builds the default-off
`experimental-windows-copy` platform library. It runs three existing stage
contract controls, five existing native checks and five named native capture
checks. The capture cases cover exact data-prefix sync, independent read-back
and EOF, failure retirement, retained-stage identity and sharing, and attribute
refusal. Relevant pushes to `main` select Stage on the `windows-2025` runner.
Manual runs can select Read, Stage or Diff and request the optional links.

Stage admits a disposable fixed-NTFS parent under the existing trusted
ancestor ACL profile and holds every ancestor without delete sharing. It
exclusively creates a synthetic fixture with a protected, inheritable
owner-only DACL. A native non-mutating control proves that the ancestor
handle mode blocks a competing DELETE open on the controlled fixture.
The original fixture remains held throughout the native tests. Cleanup
requires the same volume serial and full file ID on the live original and
the selected disposition handle, trusted ancestor and owner ACLs, no
directory entries and no named streams. It marks the selected directory
for nonrecursive removal by handle and confirms absence after close.
Uncertain custody or unexpected content fails the lane and retains the
fixture for inspection.

Artifacts include exact source and lockfile, OS and volume facts, the
inherited runner token, ancestor and fixture identities, root ACL before
and after tests, native stage observations, raw case logs and cleanup.
GitHub-hosted Windows jobs use an administrative token. The synthetic
qualification trusts the selected user, SYSTEM and local Administrators,
including a controlled fixture and no prior untrusted mutation handles.
Ordinary-user product qualification and publication durability require
separate evidence.
[GitHub-hosted runner privileges](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges).

When requested, the Stage wrapper probes symbolic-link creation inside the
same private fixture. A confirmed capability runs two existing symlink checks
and the captured identity refusal case separately. A refused privilege or
unsupported operation is retained as blocked evidence. Automatic Stage
requests the probe. Native qualification requires actual named passes and
verified fixture cleanup. See the
[private staging contract](architecture/windows-private-staging.md) for the
caller assumptions and implemented boundary.

The [`c801745` hosted Stage run](https://github.com/replicraft/ExaCopy/actions/runs/45872475625)
passed on Windows Server 2025 x64 and its fixed local NTFS volume. Independent
artifact review verified five stage cases, five capture cases, three portable
contracts, and all three optional symlink cases. The competing DELETE open
returned a sharing violation, the protected ACL was unchanged, and cleanup
deleted the original identified fixture. Earlier source-cleanup and ancestor
admission failures remain retained; they occurred before these native cases.

This hosted Stage profile admits the Windows Modules Installer owner only
at the held system-volume root, corroborated by the native system directory
and exact canonical main workflow. Other ancestors and competing-change ACEs
retain their ordinary checks. The product installer has no such exception.
This result does not qualify the separate Read or Diff modes, an ordinary
user token, another NTFS volume, UNC, full copy recovery or power loss.

The candidate starts with a directory handle supplied by the synthetic
fixture. It checks the NTFS volume and parent, searches for the exact counted
UTF-16 name, opens the observed file ID read-only, and checks identity and
membership again before issuing a byte read. The serial and bounded parallel
comparisons use the same held read views and check literal equal and unequal
byte sequences, unequal lengths and the observed extent. Other tests cover
read sharing, hard links, case and surrogate spellings, parent renames,
junction transitions, and a child moved after enumeration. This exercises
R-007, R-016, R-024, R-049, R-058, R-059 and R-067 with their acceptance cases,
and targets INV-001, INV-013, INV-016, INV-019 and INV-032.

Use a clean checkout in a disposable x64 Windows guest, official Rust 1.100.0
with MSVC, and an ordinary unprivileged account. Supply an existing writable
directory on a fixed local NTFS drive and a fresh evidence directory.

```powershell
& ./.github/ci/windows-ntfs.ps1 -Repository . `
  -LocalNtfsRoot C:\synthetic -EvidenceDirectory C:\windows-read-evidence
```

The runner verifies the local drive type, filesystem format and directory
ancestry. It creates a fresh scratch directory for synthetic files and records
the source revision, lockfile hash, profile, available storage and filter details, raw
stdout and stderr, and command exit statuses. The hosted workflow uses the
runner's profile directory for fixture data because its temporary directory can
be on a different filesystem. Optional `-UncRoot`, `-SecondNtfsRoot` and
`-IncludeSymlink` runs require a disposable SMB share, a second distinct fixed
NTFS volume and symlink permission, respectively. The manual workflow exercises
the ordinary NTFS profile.

Keep failed positive controls for the extended file-ID open and record the
original Windows error. Microsoft documents 128-bit file-reference opens on
NTFS when the high 64 bits are zero. The exact Win32 descriptor and call in this
candidate still require native evidence on that profile.
[NTFS file-ID behavior](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_objectid_information) ·
[Win32 descriptor](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_descriptor)

The fixture checks live observations over the tested profile. Parent
acquisition and path provenance, continuous membership, mapped writers,
snapshots, other filter or filesystem profiles, and publication and durability
require separate evidence. A Windows cross-build supplies compile evidence.
Native fixture results apply to the recorded Windows and storage profile.
