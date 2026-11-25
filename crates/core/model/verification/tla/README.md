# CopyRecovery model check

`CopyRecovery` models one preserve-mode publication for one regular file. The search includes two source views and run epochs, one active private stage, one public name, a pre-existing or racing incumbent, and one in-flight completion per epoch. A source change replaces the active stage before intent and can leave an old completion outstanding. Each run allows one crash at any protocol step and a restart. Interleaving is unrestricted within these bounds, with no symmetry reduction or fairness assumptions.

The model separates verification, durable intent, the namespace effect, its reported outcome, namespace barriers, and receipt. A reply can be lost before or after the effect. Recovery can recognize the same published identity, retry against an observed absent name, or preserve an incumbent and the stage. The check covers ordering and preservation within this namespace model, including `INV-002`, `INV-003`, `INV-004`, `INV-006`, and the local reconciliation part of `INV-009`.

## Assumptions and scope

- The abstract no-clobber primitive atomically moves the owned stage only when the destination name is absent. An external process can create an unrelated object at that name, including between intent and effect. The incumbent stays in place once created. The model trusts private-stage ownership and the identity and evidence observations supplied to the coordinator.
- An interruption can discard unflushed write evidence and, before the namespace barriers, can leave an owned rename in place or roll it back to its private name. Flushed data, metadata, and intent survive. `FlushNamespaces` combines all required namespace barriers into one abstract event. This is a storage contract for the model, with filesystem and power-loss qualification left to adapter evidence.
- Source-view changes are modeled as a new epoch before intent. The model accepts abstract whole-file read-back success or mismatch. It covers one publication transaction. Multi-entry scheduling, sparse ranges and resume, further crashes, and arbitrary storage corruption are outside the explored bounds. Recorded receipts are safety assertions. Liveness and deadlock are unchecked because conflicts and verification mismatch may safely stop the attempt.
- The Rust `CopySession` covers one attempt through its typed inputs and emitted effects. `Prepare` corresponds to `StagePrepared`, and the early `StartAttempt` requests authorization before `PublishIntentRecorded` can be accepted. The counterexample fixture records the physical effect that an early authorization would allow. Full trace correspondence, executor replay, and crash recovery integration remain open.

## Reproduce

Use Python 3.11 or newer, Temurin OpenJDK 21.0.8+9 on `PATH`, and the `tla2tools.jar` from the [official v1.7.4 release](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4). The downloaded jar matched the publisher's SHA-1. The gate enforces the SHA-256 and Java runtime in [toolchain.lock.json](toolchain.lock.json). TLC uses a temporary local Java RMI socket during startup.

From the repository root, run:

```sh
TLA2TOOLS_JAR=/path/to/tla2tools.jar \
  TLC_LOG_DIR=/path/to/logs \
  crates/core/model/verification/tla/check.sh
```

`TLC_LOG_DIR` is optional. Set it to retain coverage reports and the raw counterexample. The gate requires completed normal exploration, reachability of the named risk actions, and exit 12 plus an `ApplyNoClobber` trace violating `PriorPublicationEvidence` in the mutant.

## Executed result

TLC 2.19 at revision `5a47802` ran on macOS 14.7.2 Arm64 under Temurin `21.0.8+9-LTS`. Both runs used one worker, seed `0`, and fingerprint polynomial index `0`.

| Configuration | TLC exit | Generated | Distinct | Queued | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `CopyRecovery.cfg` | 0 | 474 | 204 | 0 | All nine invariants held through depth 18. |
| `CopyRecoveryEarlyPublication.cfg` | 12 | 31 | 23 | 13 | `PriorPublicationEvidence` failed at state 4. |

In the [normalized negative trace](CopyRecoveryEarlyPublication.trace.json), `Prepare` creates the private stage, `StartAttempt` bypasses intent, and `ApplyNoClobber` publishes the empty stage at the absent target. The same atomic no-clobber rule applies in both configurations.
