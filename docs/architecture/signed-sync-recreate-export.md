# Signed manual recreate proposal

The Linux `experimental-linux-managed-sync` feature adds
`sync-managed export-recreate`: one owner-authored proposal for a reviewed
create-new resolution of a one-sided CommonPresent conflict. This is a partial
implementation of R-272 and INV-026. Parent application, workflow action
records and baseline advancement remain unsupported.

The command takes the existing selected profile, owner key, selection and
Init acknowledgement, direction and reviewed conflict. It also requires an
independently selected UUIDv7 `--pair-id` and positive bounded
`--expires-in-seconds`. Parent and ordinary child share creation and exclusive
expiry times. The child still needs separate approval. Existing
`prepare-recreate`, ordinary child and P-063 encodings are unchanged.

The selected UUID is the parent's 16-byte pair identifier. The signature
explicitly associates it with the authenticated predecessor reference.
P-063's 32-byte pair digest remains distinct. Verification checks both against
independent selections; it does not establish a current pair registry or head.

## Custody and evidence

The read-only seed guard borrows the policy record's original shared profile
lease. Init keeps its exclusive writer path, and preview and unsigned
preparation remain seed-free. The producer authenticates policy and history
and observes the live pair before reading the seed. Seed buffers are zeroized,
and the derived key must match the independently selected owner.

Seed, policy and pair remain held through signing and independent verification
of the complete bundle. Postflight and expiry checks finish before stdout.
The verifier checks the exact child profile, ordered roots, raw subject,
content, required metadata, conflict reason, times and references. The native
adapter supplies both Linux identity representations from one held file
observation; the engine does not encode native device numbers.

## Canonical artifacts

The signed parent uses workflow kind 5, version 1.0, required feature mask 69
and signature domain code 32. The action page has its own workflow kind
`0x0101`. The existing closed P-063 kind enum is retained.

Parent key 7 contains two ordered coverage descriptors, each limited to the
selected subject. Its side-specific observation commitment binds both pair
identifiers, ordered endpoints, predecessor, scope, approved policy and action
page. Key 8 is a singleton action-page reference array. The child page uses
the ordinary `DocumentRef` domain.

The eight members are parent envelope, action page, ordinary child body/page
and the four exact original P-063 members. Limits are 2 KiB per member,
16 KiB decoded aggregate and 64 KiB for the newline-terminated JSON report.
The report marker is `exacopy.cli.managed_sync_recreate_export` version `1.0`.

`authority` is `none`, `approval_required` is true, and approval, delegated
grant, action intent, copy-started and baseline-advanced flags are false.
Empty parent grant references and the null action grant cannot authorize
execution. The expected Linux v1 receipt selector claims no existing receipt
and does not accept another receipt family.

## Acceptance boundary

The source includes frozen wire vectors, strict substitution and JSON controls,
and signed-export and missing-seed controls in the existing whole-ext4 CLI
fixture. Execution must be verified against the integrated revision. The two
separate platform lease tests remain ignored unless explicitly selected on
their required native fixture.

Separate parent approval, durable kind-27/28 associations, current-baseline
selection, successor persistence, restart reconciliation and P-028 publication
barriers remain open. This supplies no new Kani or power-loss qualification.
