# Initial held Windows bootstrap inspection

The opt-in `recover inspect-windows-bootstrap` command and this application
fixture share the composition of the portable journal codec and protected
fixed-NTFS record reader. They support partial read-side work toward R-039–041
and independently selected owner trust under R-046. Windows CLI copy, later
journal appends, published-stage reconciliation under R-044, and durability qualification
remain separate work. [Product selection and report](../../README.md#inspect-a-windows-job-bootstrap)

The provisioner creates a private root and two private job layouts, each
with two empty protected records. It retains the common root identity and
all eight distinct child identities. The fixture confirms and rechecks
the original held identities when populating each pair, then closes both
writers before inspection.

For the original job, the producer now closes its provisioning handles and
opens `WindowsBootstrapFreshSegment` against the independently retained five
native identities. The adapter requires the original empty segment and admits
one exclusive data writer beneath the existing protected ancestry. It supplies
bounded append, file sync and held read-back to `DurableJournal`. The fixture
confirms the actual first frame and EOF and compares the bytes with the same
canonical signed V1 artifact before using the existing reader. The copied
counterexample retains its deliberately untrusted raw-byte population.
This is a fresh first-segment mechanism toward R-040/A-040 and INV-019.
It supplies no recovery append aperture or Windows transfer command.

The native control also refuses a different selected identity, a competing
writer, an out-of-range seek and an oversized write; it refuses fresh admission
after population. These controls remain unexecuted. The adapter keeps strict
timestamp comparisons before and after file sync and retires on disagreement.
Windows guarantees accurate last-write timestamps after write handles close;
the new open-handle flush path remains unqualified. The adapter supplies no
directory barrier or power-loss claim. [File times](https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times)

The original fixture acquires `WindowsCaptureBootstrapScope` with the original
five roles and the actual job handle's child-creation rights. Its consuming
handoff checks independently supplied owner bytes, exposes a callback-scoped
writer for the real `DurableJournal` append, and confirms exact first-frame
bytes and physical EOF around a file barrier. Owner bytes are checked again
before the same held roles become `WindowsCaptureStageScope`. The fixture
refuses a mismatched owner and a successful callback that wrote nothing.
It checks segment exclusivity before and after stage work.

The stage scope samples target absence with
a case-insensitive, metadata-only lookup and exclusively creates a private
stage directory and leaf with a protected current-user ACL at creation.
Every write and prefix barrier remains bound to that custody. The callback
can close and read back the private stage; it has no target writer or
publication operation. The fixture preserves an aliased incumbent, checks
the original stage identities and bytes, refuses a repeated stage name,
and removes only its checked disposable entries before bootstrap inspection.

This tightens the experimental Rust API: the direct stage-scope constructor
is replaced by the consuming bootstrap handoff. The standalone fresh writer
and read-only inspector retain their existing entry points and V1 bytes.
Native byte checks do not authenticate the record; the application supplies
that policy. Namespace persistence and checkpoint records remain separate.

Two separately selected ordinary Windows controls check descriptor geometry
and acceptance by the existing private ACL parser, including wrong owner and
trustee refusals. Their individual JUnit reports are retained. These tests
need no provisioned NTFS fixture and do not qualify native creation. The held
scope still needs native execution on an admitted root. It supplies no SSH
capture, durable checkpoint, namespace barrier or recovery authority.

The reader admits both metadata pins before either data handle. The application
uses the owner bytes and five role values from that same holder with an
independently selected profile, job, root and RFC 8032 test key. It reports a
historical head only after portable inspection and the segment's native
`finish()` both succeed. A byte limiter or cached logical EOF cannot replace
the final held EOF probes and namespace/security rechecks.

The native case confirms the selected original history, a wrong root
serial, and a wrong verification key. It also checks both original signed
records copied verbatim into the second job. Both copied files match the
original bytes through physical EOF under different native identities.
The alternate native and logical selections use the same second UUIDv7.
Authentication refuses the copied original owner with the typed job mismatch.

The alternate segment supplies separate hardlink and named-stream refusals.
The fixture confirms both link names refer to the same object and verifies
that the targeted bytes survive each refusal. It removes the owned link
and named stream and confirms admission again before adding a one-byte
suffix. The held reader refuses the extra extent and preserves the suffix.
The original history is successfully inspected after these controls.
ACL mutation, in-flight rebinding, terminal I/O failure and crash behavior
remain outside these checks.

The reader requires a stable non-elevated primary user token, a fixed local
NTFS volume and its existing strict ancestor policy. Provisioning excludes
retained untrusted mutation capabilities. Trusted administrators and same-user
participants must refrain from mutations throughout inspection. Share flags
alone do not exclude security, attribute or stream writers.

The `windows-bootstrap-fixture` feature enables the explicit ignored test
target `windows_bootstrap`. `run.ps1` accepts a separately selected exact test
image and digest, uses owned process supervision, and removes the fixture only
after confirmed drain, exact outcome, control marker and custody checks.
Failure retains the physical fixture for that run. The historical head
is retained only after cleanup. Native execution of these controls is pending.

The `experimental-windows-bootstrap-inspect` feature enables the product command.
Ordinary Windows CI selects its exact parser, historical report and weak-key
refusal controls. The default workspace run checks that the command remains
hidden without its target and feature. These source-defined controls require
no native bootstrap provisioning. They do not qualify the held native case.

The separate `windows-ntfs-bootstrap.yml` workflow admits one exact canonical
main-push job and its source, attempt and image. Its provider checks the
checkout's existing non-system fixed-NTFS volume and keeps the native reader's
strict ancestry policy. It changes no volume or volume ACL. The controller
derives a same-SID restricted primary token and checks the planned token and
actual suspended child's session, elevation and storage privileges before
resume. The documented process API may temporarily enable a possessed caller
privilege; the provider adds no explicit privilege adjustment.

Build retirement, held image selection, process drain and fixture cleanup have
separate receipts. Ineligible volume or actor evidence fails admission without
a fallback. A passing initial fixture covers only the cases above. It does not
qualify Windows copy, restart recovery, publication or power-loss durability.

Retained attempts `46079103337` and `46070223805` refused the `D:\` volume owner
at fixed-NTFS admission. Attempt `46068832224` refused competing non-actor
access at that boundary. None reached the selected bootstrap fixture.
