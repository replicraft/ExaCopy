----------------------- MODULE WitnessedCloseoutPhase -----------------------
EXTENDS Naturals, FiniteSets

CONSTANT Mutation
VARIABLE state

RunLimit == 64
FirstSegmentMax == 67108864
ReceiptMax == 6144
SlotCeiling == 27
CheckpointBytes == 860
Widths == [k \in {37, 2, 15, 40, 3, 41, 4, 5, 6, 7, 8, 9, 42, 18, 39} |->
    CASE k = 40 -> 1116 [] k = 41 -> 697 [] k = 4 -> 635 [] k = 5 -> 567
      [] k = 6 -> 546 [] k = 7 -> 1014 [] k = 8 -> 568 [] k = 9 -> 643
      [] k = 42 -> 781 [] k = 18 -> 547 [] k = 39 -> 997 [] OTHER -> 860]

Capture == "capture"
WIntent == "41"
Seal == "4"
Verify == "5"
Metadata == "6"
Intent == "7"
Positive == "8-ok"
Durable == "9"
Ready == "42"
Complete == "18"
Retired == "39"
Allocated == "37"
Fresh == "2"
FreshProgress == "v1-fresh-covered"
Terminal == "stop"
Live == "live"
Restart == "restart"
Blocked == "blocked"
BeforeIntent == {Capture, WIntent, Seal, Verify, Metadata}
StableCoverage == {WIntent, Seal, Verify, Metadata, Intent, Positive,
                   Durable, Ready, Complete}

\* Exact maxima from independently encoded wire widths; success kind 8 costs
\* 559 framed bytes rather than the maximum across every outcome (568).
CloseBytes(phase, reusable) ==
    CASE phase = Capture -> IF reusable THEN 6022 ELSE 5989
      [] phase = WIntent -> IF reusable THEN 5325 ELSE 5292
      [] phase = Seal -> IF reusable THEN 4690 ELSE 4657
      [] phase = Verify -> IF reusable THEN 4123 ELSE 4090
      [] phase = Metadata -> IF reusable THEN 3577 ELSE 3544
      [] phase = Intent -> 2530
      [] phase = Positive -> 1971
      [] phase = Durable -> 1328
      [] phase = Ready -> 547
      [] phase = Retired -> 2580
      [] phase = Allocated -> 1720
      [] phase = Fresh -> 860
      [] OTHER -> 0

CloseSlots(phase) ==
    CASE phase = Capture -> 9 [] phase = WIntent -> 8 [] phase = Seal -> 7
      [] phase = Verify -> 6 [] phase = Metadata -> 5 [] phase = Intent -> 4
      [] phase = Positive -> 3 [] phase = Durable -> 2 [] phase = Ready -> 1
      [] phase = Retired -> 3 [] phase = Allocated -> 2 [] phase = Fresh -> 1
      [] OTHER -> 0

Advance(kind, phase, bound) ==
    [state EXCEPT !.phase = phase, !.offset = @ + bound, !.seq = @ + 1,
                  !.previous = state.seq, !.recordKind = kind]
Frame(kind, phase) == Advance(kind, phase, Widths[kind])

Init ==
    \E run \in {1, 62, 63}, room \in {7137, 7138, 8858, 12000, 15000}:
      state = [phase |-> "v1", run |-> run, epoch |-> 2 * run,
        stage |-> 1, original |-> 1, predecessorStage |-> 0, stageCount |-> 1,
        previousEpoch |-> 2 * run - 2,
        lastPass |-> 1, current |-> 1, extent |-> 1, coverage |-> 1,
        ordinal |-> 0, frozen |-> 0, offset |-> FirstSegmentMax - room,
        seq |-> IF room = 8858 THEN 17 ELSE 5,
        previous |-> IF room = 8858 THEN 16 ELSE 4, recordKind |-> 3,
        byteLimit |-> FirstSegmentMax, slotLimit |-> SlotCeiling,
        hasReserve |-> FALSE, reserveOk |-> TRUE,
        stableWitness |-> FALSE, retiredSafely |-> TRUE,
        stageRetired |-> {}, witnessedRetained |-> {}, promisedWitness |-> {},
        afterTwo |-> FALSE, retirementFrom |-> "none",
        exactAnchor |-> TRUE, freshDistinct |-> TRUE,
        process |-> Live, crashes |-> 0, receipt |-> "none",
        submissions |-> 0, receiptChanges |-> 0, uncertain |-> FALSE,
        repeatedUnknown |-> FALSE, receiptEvidence |-> TRUE, publicFact |-> FALSE,
        permit |-> FALSE, permitStamp |-> 0, usedPermit |-> FALSE,
        observation |-> "unobserved", finalConfirmed |-> FALSE, sameSessionReplay |-> FALSE]

Begin(extent, exact, fresh, short) ==
    LET requiredBytes == Widths[40] + (extent - state.coverage) * CheckpointBytes
                          + CloseBytes(Capture, state.run + 1 < RunLimit)
        requiredSlots == 1 + extent - state.coverage + CloseSlots(Capture)
        enoughBytes == state.offset + requiredBytes <= FirstSegmentMax
        enoughSlots == state.seq + requiredSlots <= SlotCeiling
        receiptBytes == IF short = "receipt" THEN 0 ELSE ReceiptMax
        bytesOk == enoughBytes /\ short # "bytes"
        slotsOk == enoughSlots /\ short # "slots"
        receiptOk == receiptBytes = ReceiptMax
        enough == bytesOk /\ slotsOk /\ receiptOk
    IN
    /\ state.phase \in {"v1", FreshProgress, Capture}
    /\ state.stage > 0
    /\ state.coverage <= extent
    /\ (state.run < RunLimit \/ Mutation = "run-limit")
    /\ (exact \/ (Mutation = "stale-repeat" /\ state.phase = Capture))
    /\ (fresh \/ (Mutation = "stale-epoch" /\ state.phase = Capture))
    /\ (bytesOk \/ Mutation = "skip-byte")
    /\ (slotsOk \/ Mutation = "skip-slot")
    /\ (receiptOk \/ Mutation = "skip-receipt")
    /\ state' = [Frame(40, Capture) EXCEPT !.run = @ + 1,
         !.previousEpoch = state.epoch, !.epoch = IF fresh THEN @ + 2 ELSE @,
         !.lastPass = state.current, !.current = state.seq + 1,
         !.afterTwo = @ \/ (state.phase = Capture /\ state.ordinal = 2),
         !.extent = extent, !.ordinal = 0, !.process = Live,
         !.byteLimit = IF short = "bytes" THEN state.offset + requiredBytes - 1
                       ELSE state.offset + requiredBytes,
         !.slotLimit = IF short = "slots" THEN state.seq + requiredSlots - 1
                       ELSE state.seq + requiredSlots,
         !.reserveOk = enough, !.hasReserve = TRUE,
         !.exactAnchor = exact,
         !.receipt = IF receiptBytes > 0 THEN "anonymous" ELSE "none",
         !.observation = "unobserved", !.finalConfirmed = FALSE, !.receiptEvidence = TRUE]

Checkpoint ==
    /\ state.phase = Capture /\ state.process = Live /\ state.coverage < state.extent
    /\ state' = [Frame(3, Capture) EXCEPT !.coverage = @ + 1, !.ordinal = @ + 1]

Witness ==
    /\ state.phase = Capture /\ state.process = Live
    /\ state.coverage = state.extent
    /\ state' = [Frame(41, WIntent) EXCEPT !.frozen = state.coverage]

SealWitness ==
    /\ state.phase = WIntent /\ state.process = Live
    /\ state' = [Frame(4, Seal) EXCEPT !.stableWitness = TRUE]

VerifyMetadata ==
    \/ /\ state.phase = Seal /\ state.process = Live
       /\ state' = [Frame(5, Verify) EXCEPT
                       !.coverage = IF Mutation = "move-coverage" THEN @ - 1 ELSE @]
    \/ /\ state.phase = Verify /\ state.process = Live
       /\ state' = Frame(6, Metadata)
    \/ /\ state.phase = Metadata /\ state.process = Live
       /\ state' = Frame(7, Intent)

Retire(withWitness) ==
    LET permitted == state.phase \in BeforeIntent
                     /\ (state.phase # Capture \/ ~withWitness)
                     /\ (state.phase \notin {Seal, Verify, Metadata} \/ withWitness)
    IN
    /\ (permitted \/ (Mutation = "retire-after-intent" /\ state.phase = Intent))
    /\ state.run < RunLimit
    /\ state' = [Frame(39, Retired) EXCEPT !.retiredSafely = permitted,
        !.stableWitness = withWitness, !.frozen = 0, !.receipt = "none",
        !.retirementFrom = state.phase, !.stageRetired = @ \cup {state.stage},
        !.witnessedRetained = IF withWitness THEN @ \cup {state.stage} ELSE @,
        !.promisedWitness = IF withWitness THEN @ \cup {state.stage} ELSE @]

Allocate ==
    /\ state.phase = Retired /\ state.stageCount = 1 /\ state.run < RunLimit
    /\ state' = [Frame(37, Allocated) EXCEPT !.stage = 0,
        !.predecessorStage = state.stage, !.run = @ + 1,
        !.previousEpoch = state.epoch, !.epoch = @ + 2,
        !.original = state.seq + 1, !.current = state.seq + 1, !.coverage = 0]

Prepare ==
    /\ state.phase = Allocated
    /\ state' = [Frame(2, Fresh) EXCEPT !.stage = IF Mutation = "reuse-stage" THEN 1 ELSE 2,
        !.freshDistinct = (IF Mutation = "reuse-stage" THEN 1 ELSE 2) # state.predecessorStage,
        !.stageCount = 2,
        !.witnessedRetained = IF Mutation = "drop-retained" THEN {} ELSE @,
        !.coverage = 0, !.extent = 1, !.ordinal = 0, !.stableWitness = FALSE]

FreshCheckpoint ==
    /\ state.phase = Fresh /\ state.process # Blocked
    /\ state.offset + CheckpointBytes <= FirstSegmentMax /\ state.seq + 1 <= SlotCeiling
    \* The fresh V1 writer independently reserves this data/record.
    /\ state' = [Frame(3, FreshProgress) EXCEPT !.coverage = 1, !.ordinal = 1,
        !.hasReserve = FALSE]

Failure ==
    /\ state.phase \in BeforeIntent \cup {Allocated, Fresh}
    /\ state' = Frame(15, Terminal)

SubmitPublic ==
    /\ state.phase = Intent /\ state.process = Live /\ ~state.publicFact
    /\ state' = [state EXCEPT !.publicFact = TRUE]

ObservePositive ==
    /\ state.phase = Intent /\ state.publicFact
    /\ state' = Advance(8, Positive, 559)

ObserveTerminal ==
    /\ state.phase = Intent
    /\ state' = Frame(8, Terminal)

SyncPublication ==
    /\ state.phase = Positive
    /\ state' = Frame(9, Durable)

SealPending ==
    /\ state.phase = Durable /\ state.receipt = "anonymous" /\ state.process = Live
    /\ state' = [state EXCEPT !.receipt = "exact-pending", !.observation = "pending"]

ObserveReceipt(complete) ==
    /\ state.phase \in {Durable, Ready} /\ state.process # Blocked
    /\ state' = [state EXCEPT !.observation =
        IF complete /\ state.receipt = "exact-pending" THEN "pending" ELSE "unconfirmed",
        !.permit = IF complete /\ state.receipt = "exact-pending" THEN @ ELSE FALSE,
        !.finalConfirmed = FALSE]

RecordReady ==
    /\ state.phase = Durable /\ state.process # Blocked
    /\ ((state.receipt = "exact-pending" /\ state.observation = "pending") \/ Mutation = "digest-only")
    /\ state' = [Frame(42, Ready) EXCEPT !.receiptEvidence = (state.receipt = "exact-pending" /\ state.observation = "pending")]

AuthorizeReceipt ==
    /\ state.phase = Ready /\ state.receipt = "exact-pending"
    /\ ((state.process \in {Live, Restart} /\ ~state.usedPermit)
        \/ (Mutation = "reuse-unknown" /\ state.process = Blocked))
    /\ state.publicFact /\ state.observation = "pending" /\ ~state.permit
    \* This is the fresh lease, live grant and consent plus exact current held
    \* witness/target/receipt observation and barrier premise, including restart.
    /\ state' = [state EXCEPT !.permit = TRUE, !.permitStamp = state.crashes]

Promote(effect, known) ==
    /\ state.phase = Ready /\ state.receipt = "exact-pending"
    /\ state.submissions < 2
    /\ (state.process \in {Live, Restart} \/ Mutation = "reuse-unknown")
    /\ state.permit /\ state.observation = "pending"
    /\ (~known \/ effect)
    /\ state' = [state EXCEPT !.receipt = IF effect THEN "exact-final" ELSE @,
        !.submissions = @ + 1, !.receiptChanges = IF effect THEN @ + 1 ELSE @,
        !.process = IF known THEN @ ELSE Blocked,
        !.permit = FALSE, !.usedPermit = TRUE,
        !.observation = CASE Mutation = "commit-before-barriers" /\ known /\ effect -> "final"
                          [] Mutation = "reuse-unknown" /\ ~known -> @
                          [] OTHER -> "unobserved",
        !.finalConfirmed = FALSE,
        !.sameSessionReplay = @ \/ state.process = Blocked,
        !.uncertain = @ \/ ~known,
        !.repeatedUnknown = @ \/ state.uncertain]

ConfirmFinal ==
    /\ state.phase = Ready /\ state.receipt = "exact-final" /\ state.process # Blocked
    /\ state.publicFact
    \* This event requires positive exact final and public/witness readback
    \* and the qualified required artifact and directory barriers.
    /\ state' = [state EXCEPT !.observation = "final", !.finalConfirmed = TRUE]

RecordCommit ==
    /\ state.phase = Ready /\ state.receipt = "exact-final" /\ state.process # Blocked
    /\ state.observation = "final"
    /\ state' = Frame(18, Complete)

CrashReopen ==
    /\ state.crashes = 0 /\ state.phase \notin {"v1", Complete, Terminal}
    /\ state' = [state EXCEPT !.process = Restart, !.crashes = 1,
        !.receipt = IF @ = "anonymous" THEN "none" ELSE @,
        !.permit = Mutation = "revive-permit" /\ state.permit, !.usedPermit = FALSE,
        !.observation = "unobserved", !.finalConfirmed = FALSE]

BeginSupply ==
    \E extent \in {1, 3}, exact, fresh \in BOOLEAN,
       short \in {"none", "bytes", "slots", "receipt"}:
         Begin(extent, exact, fresh, short)

FirstContinuation == state.phase = "v1" /\ BeginSupply
RepeatContinuation == state.phase = Capture /\ BeginSupply
FreshContinuation == state.phase = FreshProgress /\ BeginSupply

Next ==
    \/ FirstContinuation \/ RepeatContinuation \/ FreshContinuation
    \/ Checkpoint \/ Witness \/ SealWitness \/ VerifyMetadata
    \/ \E withWitness \in BOOLEAN: Retire(withWitness)
    \/ Allocate \/ Prepare \/ FreshCheckpoint \/ Failure \/ SubmitPublic \/ ObservePositive \/ ObserveTerminal
    \/ SyncPublication \/ SealPending \/ RecordReady \/ AuthorizeReceipt
    \/ \E complete \in BOOLEAN: ObserveReceipt(complete)
    \/ \E effect, known \in BOOLEAN: Promote(effect, known)
    \/ ConfirmFinal \/ RecordCommit \/ CrashReopen

BoundedAndExact ==
    /\ state.run <= RunLimit /\ state.offset <= FirstSegmentMax
    /\ state.seq <= SlotCeiling /\ state.epoch > state.previousEpoch
    /\ state.seq = state.previous + 1
    /\ state.exactAnchor /\ state.freshDistinct /\ state.retiredSafely
    /\ state.promisedWitness = state.witnessedRetained
    /\ (state.phase \in {Fresh, FreshProgress} => state.stage \notin state.stageRetired)

ReservedCapacity ==
    /\ state.reserveOk
    /\ ((state.hasReserve /\ state.phase # Terminal) =>
        /\ state.offset + CloseBytes(state.phase, state.run < RunLimit)
           + (IF state.phase = Capture THEN
                    (state.extent - state.coverage) * CheckpointBytes ELSE 0)
            <= state.byteLimit
        /\ state.seq + CloseSlots(state.phase)
           + (IF state.phase = Capture THEN state.extent - state.coverage ELSE 0)
            <= state.slotLimit)

CoverageFence ==
    state.phase \in StableCoverage => state.coverage = state.extent /\ state.coverage = state.frozen

CustodyFence ==
    /\ (state.phase \in {Ready, Complete} => state.receiptEvidence)
    /\ (state.phase = Complete => state.receipt = "exact-final" /\ state.finalConfirmed)
    /\ state.receiptChanges <= 1 /\ ~state.sameSessionReplay
    /\ (state.process = Blocked => state.phase = Ready)

CurrentReceiptPermit == state.permit => state.permitStamp = state.crashes

NoResubmitAfterUnknown == ~state.repeatedUnknown

ReachedRepeatAfterTwo == ~state.afterTwo
ReachedLateRetire == state.retirementFrom # Metadata
ReachedPassLimitCloseout == ~(state.run = RunLimit /\ state.phase = Complete)

Spec == Init /\ [][Next]_state
=============================================================================
