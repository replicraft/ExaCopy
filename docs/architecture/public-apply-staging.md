# Staging approved public content

`exacopy-transfer::linux::stage_public_apply` stages one admitted public
create-new Plan through the existing read/create/write capabilities. It
matches public and private root aliases, raw basenames, native source
identity, private entry/epoch, approved length and digest, metadata policy,
buffer budget and admission/expiry interval before bootstrap.

The coordinator persists and synchronizes the [public-apply owner](public-apply-owner.md)
before the first JobPrepared record. Its complete signed digest binds that
journal. Legacy owner and recovery readers refuse this form. The private
Plan and its digest keep their existing representation.

Staging captures the actual copied source stream's length and BLAKE3 digest
and the independent stage read-back length and digest. All four must match
the authenticated expectations before durable seal evidence is appended.
A source and stage that match each other but differ from the approved
content are refused. Metadata remains governed by the existing narrow
Linux baseline policy. Created private artifacts remain for reconciliation
on failure.

The only successful result is the signed owner's digest. No publication
intent, rename, stage handle or publication permission is returned. This
is not a public apply command. Fresh expiry and native process-crash
eligibility must gate eventual publication; public-aware inspection,
resume and retry are separate work. No native durability claim follows
from requesting process-crash durability in the Plan.

The exact Linux-target transfer tests and implementation passed strict
cross Clippy. A separately labeled macOS portable capability fixture ran
85 transfer tests. Five guard-removal controls failed their expected
assertions, covering each approved stream comparison and private entry
binding. This portable fixture temporarily exposes Linux coordinators for
testing and does not execute the native Linux adapter. Raw results and
exact source hashes remain in
`/private/tmp/exacopy-public-apply-stage.7f8wBxAQ/review.md`.

The later hosted whole-ext4 fixture at `09b96f5` exercised the real
private staging coordinator and independently reopened its result under
a read lease. Public apply, commit and interruption qualification remain
open. [Native staging and inspection result](public-stage-inspection.md#native-stage-and-inspection-evidence)
