# Managed create-new action ordering

The model covers the sequencing of one approved CommonPresent recreate action with one pre-existing protected ledger slot, two contenders, and at most one process restart. It is an abstract R-272 and INV-026 prerequisite. A production executable profile, wire encoding, native issuer and implementation correspondence remain separate. P-027 concerns classification. P-028 covers separate baseline advancement, which this model does not perform.

## Assumptions and scope

The independently trusted issuer atomically and durably spends the single activation before any append admission. A grant and exclusive pair/slot custody remain live for each admitted effect. The two contender indices identify distinguishable scope-bound attempts. Scalar labels abstract exact independently selected activation, ledger, child Plan, entry, receipt and head semantics. The selection distinguishes an independently confirmed current generation from stale selection. The single ready slot starts with one trusted prepared anchor. Its empty suffix is distinct from issuer spend. One process holds the slot and can start child mutation only after the original slot's kind-27 barrier and separate semantic and physical reread.

Child job creation and child public submission are distinct. A verified child terminal is a truthful same-attempt projection of checked outer v2 receipt and child kind-18 evidence. Conflict, unknown and incomplete settlement are separate terminal projections. The model assumes truthfulness of these facts, held namespace correspondence and no-clobber of the real child. Signed encoding, Linux syscall effects, recovered write authority and power-loss behavior are outside the model's scope. An already admitted write or submitted child operation can finish after revocation. Revocation prevents any newly admitted effect. Restart loses the live grant.

## Checks

The healthy configuration requires one activation and one child creation at most, confirmed parent intent at creation admission, same-attempt receipt linkage, separate kind-28 persistence and reread before confirmation, and refusal to associate while uncertain. The competing claimant while the grant is live and a later requester observing the old pristine suffix can be refused without modifying the ledger. The state bounds reserve a second activation and creation solely to expose invalid behavior in the controls.

| Control | Single weakened gate | Required invariant |
|---|---|---|
| EarlyCreate | Start the job after intent persistence without parent reread confirmation. | CreateRequiresConfirmedIntent |
| DuplicateCreate | Re-admit CreateJob while the first creation result remains pending. | AtMostOneChildCreation |
| TrustPristine | Reissue durable activation to the other contender after an admitted intent was interrupted without changing the prepared suffix. | AtMostOneActivation |
| ForeignReceipt | Accept a plausible v2 terminal from an unrelated attempt when submitting kind 28. | AssociationRequiresBoundReceipt |
| EarlyAssociation | Confirm kind 28 before separate durable evidence and readback. | AssociationRequiresConfirmedEvidence |

The owner check requires healthy exhaustion and positive attendance of lifecycle edges, including successful association, both kinds' persistence and reread, conflict, uncertainty, competing refusal and pristine-suffix restart refusal. Each weakening must fail its named invariant with matching ordered causal actions. The first run remains necessary to verify actual TLC output and transition coverage. Only independent issuer evidence distinguishes an unused activation from a spent activation with the same prepared journal bytes.

## Execution and evidence

Use the TLC JAR and Temurin runtime pinned in [toolchain.lock.json](toolchain.lock.json).
The registered entry point is `verification/check.sh tlc` under this crate.
It runs the existing owner models and this model. To select this model and
its transcript controls alone, run from the workspace root:

```sh
TLA2TOOLS_JAR=/absolute/path/to/tla2tools.jar TLC_LOG_DIR=/absolute/path/to/logs \
  crates/foundation/exacopy-model/verification/tla/check-managed-action.sh
```

The runner stages the pinned JAR, model and configurations in task-owned
scratch. It hashes its source inputs before and after execution, requires
all 23 healthy action labels, and retains named logs and mirrored reports
for each attended case. Every accepted report must fit the 4 MiB bound.
An oversized report refuses acceptance and records its bounded preview,
complete digest and size. Each invocation has a 120-second timeout and
a 256 MiB Java heap. Scratch is removed on exit.

Deadlock checking is disabled. Terminal states may stutter, and there is
no fairness or liveness claim. These bounds and assumptions do not supply
native process-crash or power-loss qualification.
