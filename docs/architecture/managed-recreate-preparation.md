# Read-only managed recreate preparation

The default-off Linux SDK prepares and checks conditional approval artifacts
for one reviewed create-new action. `with_scoped_prepared_recreate` lends a
read-only observation while the original profile, live pair and selected
action slot remain held. It creates no claim, writer, live grant or child.
Current-selector authority, attestation qualification and baseline advancement
remain separate, unfinished operations.

Both `experimental-linux-managed-sync` and `experimental-linux-public-apply`
are required for the application SDK. It adds no CLI execution command.
The existing signed review and action page 257 remain review-only.

## Independent selection and approval

The caller selects the existing profile, canonical owner key, selection ID
and retained Init acknowledgement. The SDK reopens that acknowledged profile
read-only. It checks the exact signed review, predecessor and ordinary child
Plan against fresh held observations and an independently selected private
attempt. It never repeats Init or derives trust from candidate artifact bytes.

The first profile requires the same owner key and profile for managed and
ordinary records. Approver and qualification-attestor keys are canonical,
strong, and distinct from each other and the owner. Actual attestation
verification is still required before future execution.

| Artifact | Magic | Exact bytes |
| --- | --- | ---: |
| Host selection H | `EXMAH001` | 838 |
| Scoped grant G | `EXMAG001` | 293 |
| Executable parent E | `EXMAE001` | 268 |
| Activation A | `EXMAA001` | 196-byte body plus 64-byte signature |

Each private dialect has version 1.0 and zero required features. The SDK
rebuilds exact canonical bytes from selected facts. H is checked against an
independently retained digest. G binds H and the action; E binds G and the
review; A binds the finalized artifacts under a distinct approver signature.
The unsigned-body confirmation and complete signed-envelope commitments have
different BLAKE3 derive-key contexts. Signing requires explicit confirmation
of the body digest; verification requires the independent envelope pin.
These records are separate from public Workflow Root encodings.

## Original custody and origin

The order is original profile SH, common-parent EX, then selected slot EX.
There is no shared-to-exclusive upgrade or unlocked reopen. Full physical
ancestry checks admit only the intended profile/direct-slot and
common-parent/direct-root relationships. The fixed segment is an exact
single-link, owner-private regular file, opened read-only without following
links. Slot and segment ordinary and unique mount identities are checked.

The platform serializes actual held native facts into bounded, role-separated
preimages. The app hashes them under separate slot and segment contexts.
Boot, namespaces, storage mount, actor, profile, slot, segment and exact raw
slot name are bound. Extent and timestamps are checked as custody facts and
are excluded from stable role commitments.

The prepared origin is a 340-byte body in one 432-byte common V1 frame:
kind 45, sequence one, zero previous digest. The matcher compares every field
and the external head and extent. Ordinary readers continue refusing kind 45
at the header discriminator, including a truncated frame; only the private
matcher opts in. Matching a slice establishes no physical EOF or barrier.

The SDK separately reads the original segment through physical EOF into a
private fixed-size buffer. One 16-interruption allowance spans each segment
read and its EOF probe. Legacy policy rechecks retain their existing std I/O
behavior; this is not a uniform retry bound for the whole invocation.
The last accepted UTC sample is retained across approval verification,
callback entry and postflight. External clock calls precede the final subject
and exact-origin rechecks. Late errors discard the staged observation.

## Evidence and remaining execution boundary

P-087 selects one independent body, frame and boundary specimen. Separate
tests cover malformed fields, independent substitutions, and ordinary-reader
refusal. Five approval wire tests use frozen bytes, digests and signatures.
The combined-feature native job separately checks its library, CLI and
integration-test artifacts and exact attendance. The original singleton
managed-sync job and its evidence remain separate.

Native controls are defined for wrong pins, roles and origins; byte-identical
segment replacement; incompatible locks and release; clock regressions,
expiry and unavailability; and callback-time metadata changes. Integrated
execution results are pending. These controls qualify neither actual current
selection nor attestation, child execution, restart or power-loss durability.

Execution still needs independently current selection and qualified ordinary
admission, durable one-use claim creation, confirmed kind 27 before the actual
child mkdir, phase-aware parent custody, and kind 28 from the same held child
receipt. The [execution design](signed-sync-recreate-execution.md) retains
those requirements. Baseline persistence and current-pointer activation
remain separate acceptance gates.
