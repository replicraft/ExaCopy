# Protected witness namespace model

`WitnessNamespace.tla` is an independent finite kernel and process
model of the retained-append protected witness profile. It has two
reusable inode slots, an original stage name, a protected witness name,
a public target and one extra alias. It tracks three open references,
one modeled process crash and restart, independent grant and consent
expiry, and a definite or lost native reply. Its internal slot-origin
labels are unavailable to the policy. The protected witness and job
namespace stay outside external mutation. The public target may be
created or removed by another actor.

Allocation requires no remaining links and no remaining open references.
A successful no-replace rename moves the stage name to the public name
without unlinking the protected witness. Restart drops volatile
submission rights and open references. Recovering a positive
observation requires the current public name and protected witness to
refer to the exact held original inode with exactly two links, and the
old stage must be positively absent. The positive result describes that
observation point. An external unlink after that point can remove the
public name while the witness still pins the same inode.

The four weakening controls allow incorrect inode reuse despite a
witness, accept a witness while the target is absent, accept a stale
held target descriptor after the target was unlinked, or allow a
new process to submit the earlier rename intent. The script requires
the matching invariant and action in each counterexample. The healthy
configuration requires reachable publication, restart, external
replacement/extra alias, loss of inspection and late-success
observation transitions.

The executable Rust model checks exact typed current historical and
lease bindings, submitted logical tokens and retained aliases. Its
tests compare 65,536 independent held observation combinations,
exercise finite inode lifetime and no-replace scenarios with a separate
kernel oracle, and verify late known results. The Rust conditions and
TLA+ transitions have separate evidence. No extraction/refinement proof
or native crash durability result is asserted.

## Recovered kind-8 correspondence

P-066 applies to the observation at an exact historical kind 7. The
transfer coordinator constructs this observation through the supplied
holder and journal APIs. The following source correspondence connects its
checks to the pure model and names the checks outside the finite namespace
model.

| Coordinator or journal check | P-066 correspondence |
| --- | --- |
| Scan from byte zero with the independently selected owner, scope and qualification. Require clean kind 7 at the current held EOF and recheck the same segment and lease. | `observe_recovery` requires the historical scope and head to equal the current binding. TLC supplies the reopened process and `rename-intent` phase as abstract facts. Exact frame ancestry, authentication and EOF are journal and holder premises. |
| Check public custody and current metadata, measure the held file from byte zero, compare the digest and recheck custody around the measurement. | `Aliases::WitnessedTarget` and TLC `ExactAfterRename` require the same original inode at both current names, exactly two links and positive absence of the old private name. `RecoveryReadback::Complete` represents matching bytes, EOF and metadata. TLC abstracts reliable inspection with one flag. |
| Submit only the prepared tag 4 through the exclusive holder's final gate. | Pure `LiveBinding::admitted` requires the exact qualification, grant, matching independent approval and known time strictly before the approval deadline. TLC models grant and consent separately in `Authorized`. The concrete holder owns these final checks through submission, including the lease, identity, name and journal rechecks and frame capacity. |
| Consume the holder on every outcome, with one append call after positive observation. Refuse an unconfirmed successor and retain the last confirmed kind-7 cut as diagnostic evidence. | TLC `RecoverPublished` changes the observation phase without changing the names, and `AtMostOneLiveSubmission` excludes a post-restart rename. The pure positive result describes one observation and carries no effect capability. The coordinator exposes only a recovered journal append. Its exact bytes, barrier, reread and appender poison are beyond that model. |

The [journal regression](../../../../storage/exacopy-journal/tests/remote_continuation/witnessed_recovered_observation.rs)
compares the proposal with the existing frozen `recovered` vector at kind 8.
It checks exact predecessor and successor, rejects live tag 1, later or
unclean history, and tests refusal on a wrong phase, owner, witness or target.
The [independent vector generator](../../../../storage/exacopy-journal/verification/remote_download/witnessed_replay.py)
builds the recovered branch from the same kind-7 cut as the live branch.

The [transfer regression](../../../../engines/exacopy-transfer/tests/remote_resume/allocations/prefix/continued/handoff/prepublication/recovery.rs)
has ten synthetic holder scenarios. One confirms success with one canonical
tag-4 append, full read-back of the four-byte file and a fresh scan. Six
prevent the append for a private stage, a missing target, lost custody during
measurement, a changed digest, an already recorded successor or a native EOF
mismatch. Three attempt the append and then require reconciliation after a
different valid successor, a rebound journal during confirmation or an
uncertain append. In all three, the fixture retains the emitted bytes and
checks that the result supplies no confirmed successor. The witness-only
case corresponds to TLC's `witness-alone` control. The custody-loss case
covers a distinct concrete observation failure while a held descriptor still
reads, alongside TLC's `stale-target` control for an unlinked public name.
The `reuse-witnessed` and `revive-rename` controls concern inode lifetime and
rename authority in the abstract model.

These comparisons leave native premises open. The application must select
the exact OP2 profile and current grant and retention approval, including
the deadline, independently of history. The platform must establish
continuous protection and same-mount held identity for the original inode,
both names and the required directories. The exclusive writer must check
the lease, exact clean boundary and sufficient capacity at submission,
synchronize and independently reread the successor, and poison itself
after a possibly started append fails. The synthetic holder supplies
these observations or selected failures. Native clock expiry, qualification
drift, actual barriers and the full 24-family OP2 campaign remain open.
A confirmed tag 4 supplies a
journal boundary for separately admitted kind-9 and receipt closeout.

[Transfer coordinator](../../../../engines/exacopy-transfer/src/remote_witnessed_recovery.rs) ·
[Journal proposal and confirmation](../../../../storage/exacopy-journal/src/remote_download/witness/replay/prepublication.rs)

Run with the crate's pinned TLC jar and Java runtime.

```sh
python3 -B crates/foundation/exacopy-model/verification/tla/check-witness-namespace.py
cargo test --locked -p exacopy-model --test witnessed_publication
```

Native custody, authentication, verified readback, exact durable journal
ancestry and held authorization through each syscall are external
assumptions of the pure API. A failed or uncertain journal append remains
a native appender poison condition even when a submitted syscall result
can be reported. Receipt promotion and persistent witness retirement
remain separate protocols.
