# Native strict APFS copy through receipt

The [manual hosted workflow](../../../../.github/workflows/macos-apfs-publication.yml)
selects one ignored `exacopy-cli` assembly fixture on native ARM64 macOS 15.
Both profiles use the same native SDK call, held source and destination,
strict metadata policy, exclusive publication and receipt path. The
pinned dependency verifier checks the clean Pomologie APFS commit, tree
and archive digest before building. The workflow retains exact revision,
runner, tool, command and exit evidence alongside the nextest report.

Run the default `ordinary` profile first. Its new, owner-private synthetic
source uses the modification time from its original data write. The
`timestamp-eligible` diagnostic creates a separate synthetic source with
modification time one hour ahead of the runner's wall clock, before ExaCopy
observes the file. This isolates an input for which installing the
required mtime should leave the later-created stage's birth time intact.
The diagnostic supplies no evidence for ordinary source times. Each run
keeps the native file clock, both xattr inventories and the production
birth-time and identity checks. There is no xattr removal, source
adjustment after admission or modification of the stage's birth time in
fixture setup.

The oracle requires the prepared stage identity to reach the public name
with its original birth time through nanosecond precision, the source's
required access/modification times and mode/owner/group, exact synthetic
content at both names, removal of the private stage name, and all nine
expected journal frames. It checks that the actual receipt file matches
the returned canonical receipt, that the persisted journal, receipt and final
commitment all bind to the same publication, and that a second attempt is refused.
An unsupported managed root, strict xattr rejection, or independently observed Darwin stage-birth
adjustment reports `qualification=blocked` and fails the invocation.
When source admission or private copy stops on one of those known refusal
paths, the oracle checks source bytes and public target absence. If the
private copy had started, it checks the retained stage identity, the absence
of publication intent and later publication frames in the journal, and the
absence of a receipt. Other unexpected errors also fail. A zero-test selection
is an error.

From the repository root, with the pinned APFS and transport sources,
Rust 1.100.0 and nextest 0.9.151 already provisioned:

```sh
bash apps/exacopy-cli/verification/macos_apfs_publication/run.sh ordinary
bash apps/exacopy-cli/verification/macos_apfs_publication/run.sh timestamp-eligible
```

This fixture exercises INV-001–006 and INV-019–020 for a single synthetic
strict APFS copy. The `experimental-apfs-copy` assembly feature remains opt-in,
with the macOS copy CLI disabled. Native success on an eligible host is still
awaiting execution.
The [earlier native refusals](../../../../docs/engineering/proposed-apfs-metadata-and-birth-handoff.md)
remain evidence. The fixture supplies no restart, process-crash or
power-loss qualification.
