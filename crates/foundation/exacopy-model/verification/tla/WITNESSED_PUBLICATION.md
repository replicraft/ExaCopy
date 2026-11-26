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
