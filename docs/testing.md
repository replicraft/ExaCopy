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
| Fuzzing | Follow the [endpoint corpus](../crates/endpoints/endpoint/fuzz/README.md), [journal corpus](../crates/storage/journal/fuzz/README.md), and [public manifest verification guide](../crates/core/codec/verification/manifest/README.md). Keep targets and corpora crate-local. Include seeded accepted cases and malformed or adversarial inputs. |
| Benchmarks | Keep benchmarks with their crate. Measure verified operations under the same integrity and durability policies. |
| Formal checks | Follow the [verification guide](verification.md) and the owning crate's gate. |

The [feature matrix](specs/features/matrix.json) defines supported
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

## Windows held-directory NTFS qualification

The [manual Windows workflow](../.github/workflows/windows-ntfs-qualification.yml)
runs the `windows_read` integration test with the default-off
`windows-read-fixture` feature. The four parser tests are portable. Every
Windows filesystem test is ignored by the ordinary workspace test run,
including with `--all-features`. The manual workflow selects eleven tests
for the ordinary NTFS profile and requires all eleven to pass.

The same manual workflow's Stage selection builds the default-off
`experimental-windows-copy` platform library. It runs the three stage
contract controls and five ordinary fixed-NTFS stage tests. Enable
`include_symlink` to select the two additional symbolic-link cases on a
runner with permission to create links. These cases cover both an existing
referent and a dangling link whose referent must stay absent. The local
runner selects this suite with `-Mode Stage` and optionally
`-IncludeSymlink`. The workflow's default Read selection continues to run
the existing read qualification. See the
[private staging contract](architecture/windows-private-staging.md) for its
caller assumptions and implemented boundary. The PowerShell scripts pass
syntax parsing on macOS; native Windows execution remains pending.

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
