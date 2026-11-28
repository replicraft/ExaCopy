# Initial held Windows bootstrap inspection

The opt-in `recover inspect-windows-bootstrap` command and this application
fixture share the composition of the portable journal codec and protected
fixed-NTFS record reader. They support partial read-side work toward R-039–041
and independently selected owner trust under R-046. Windows CLI copy, journal
append, published-stage reconciliation under R-044, and durability qualification
remain separate work. [Product selection and report](../../README.md#inspect-a-windows-job-bootstrap)

The provisioner creates a private root and two private job layouts, each
with two empty protected records. It retains the common root identity and
all eight distinct child identities. The fixture confirms and rechecks
the original held identities when populating each pair, then closes both
writers before inspection.

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
