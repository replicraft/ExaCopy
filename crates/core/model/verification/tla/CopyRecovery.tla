--------------------------- MODULE CopyRecovery ---------------------------

CONSTANT AllowEarlyPublication

InitialEpoch == "initial view"
NextEpoch == "changed view"
Epochs == {InitialEpoch, NextEpoch}
NoEpoch == "no epoch"
Absent == <<"absent", NoEpoch>>
Incumbent == <<"incumbent", NoEpoch>>
OwnedObject(epoch) == <<"owned stage", epoch>>
OwnedObjects == {OwnedObject(epoch) : epoch \in Epochs}

EvidenceStates == {"empty", "written", "sealed", "data flushed", "verified",
                   "mismatch", "metadata flushed"}
AttemptStates == {"idle", "in flight", "uncertain", "observed", "conflict"}

VARIABLES epoch, pending, acceptedEpoch, evidence, stage, target,
          incumbentArrived, intent, attempt, namespaceFlushed, receipt,
          running, crashAvailable

vars == <<epoch, pending, acceptedEpoch, evidence, stage, target,
          incumbentArrived, intent, attempt, namespaceFlushed, receipt,
          running, crashAvailable>>

Init ==
    /\ epoch = InitialEpoch
    /\ pending = {}
    /\ acceptedEpoch = NoEpoch
    /\ evidence = "empty"
    /\ stage = Absent
    /\ target \in {Absent, Incumbent}
    /\ incumbentArrived = (target = Incumbent)
    /\ intent = Absent
    /\ attempt = "idle"
    /\ namespaceFlushed = FALSE
    /\ receipt = FALSE
    /\ running = TRUE
    /\ crashAvailable = TRUE

Prepare ==
    /\ running /\ stage = Absent /\ target \notin OwnedObjects
    /\ stage' = OwnedObject(epoch)
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable>>

SubmitWrite ==
    /\ running /\ stage = OwnedObject(epoch) /\ evidence = "empty"
    /\ epoch \notin pending
    /\ pending' = pending \cup {epoch}
    /\ UNCHANGED <<epoch, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable>>

AcceptWrite(epochOfCompletion) ==
    /\ running /\ epochOfCompletion \in pending
    /\ epochOfCompletion = epoch /\ stage = OwnedObject(epoch)
    /\ evidence = "empty"
    /\ pending' = pending \ {epochOfCompletion}
    /\ acceptedEpoch' = epochOfCompletion
    /\ evidence' = "written"
    /\ UNCHANGED <<epoch, stage, target, incumbentArrived, intent, attempt,
                   namespaceFlushed, receipt, running, crashAvailable>>

DiscardLateWrite(epochOfCompletion) ==
    /\ running /\ epochOfCompletion \in pending /\ epochOfCompletion # epoch
    /\ pending' = pending \ {epochOfCompletion}
    /\ UNCHANGED <<epoch, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable>>

ChangeSourceView ==
    /\ running /\ epoch = InitialEpoch /\ stage = OwnedObject(epoch)
    /\ intent = Absent /\ attempt = "idle"
    \* The old stage is retained outside the active stage slot.
    /\ epoch' = NextEpoch
    /\ stage' = OwnedObject(NextEpoch)
    /\ evidence' = "empty"
    /\ acceptedEpoch' = NoEpoch
    /\ UNCHANGED <<pending, target, incumbentArrived, intent, attempt,
                   namespaceFlushed, receipt, running, crashAvailable>>

AdvanceEvidence(from, to) ==
    /\ running /\ stage = OwnedObject(epoch) /\ evidence = from
    /\ evidence' = to
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable>>

Seal == /\ epoch \notin pending
        /\ AdvanceEvidence("written", "sealed")
FlushData == AdvanceEvidence("sealed", "data flushed")
ReadBackMatch == AdvanceEvidence("data flushed", "verified")
ReadBackMismatch == AdvanceEvidence("data flushed", "mismatch")
FlushRequiredMetadata == AdvanceEvidence("verified", "metadata flushed")

PersistIntent ==
    /\ running /\ intent = Absent /\ stage = OwnedObject(epoch)
    /\ evidence = "metadata flushed"
    /\ intent' = stage
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, attempt, namespaceFlushed, receipt,
                   running, crashAvailable>>

StartAttempt ==
    /\ running /\ attempt = "idle" /\ stage = OwnedObject(epoch)
    /\ AllowEarlyPublication \/ intent = stage
    /\ attempt' = "in flight"
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, namespaceFlushed, receipt,
                   running, crashAvailable>>

ExternalArrival ==
    /\ target = Absent /\ ~incumbentArrived
    /\ target' = Incumbent /\ incumbentArrived' = TRUE
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, intent,
                   attempt, namespaceFlushed, receipt, running, crashAvailable>>

ApplyNoClobber ==
    /\ running /\ attempt = "in flight" /\ stage = OwnedObject(epoch)
    \* The same atomic move applies to normal and mutant configurations.
    /\ target = Absent
    /\ stage' = Absent /\ target' = stage
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, incumbentArrived,
                   intent, attempt, namespaceFlushed, receipt, running,
                   crashAvailable>>

LoseReply ==
    /\ running /\ attempt = "in flight"
    /\ attempt' = "uncertain"
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, namespaceFlushed, receipt,
                   running, crashAvailable>>

LoseReplyBeforeEffect == /\ stage # Absent /\ LoseReply
LoseReplyAfterEffect == /\ target \in OwnedObjects /\ LoseReply

ResolveAttempt(result) ==
    /\ running /\ attempt \in {"in flight", "uncertain"}
    /\ intent = OwnedObject(epoch) /\ evidence = "metadata flushed"
    /\ attempt' = result
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, namespaceFlushed, receipt,
                   running, crashAvailable>>

ObservePublished ==
    /\ attempt = "in flight" /\ target = intent
    /\ ResolveAttempt("observed")

ReconcilePublished ==
    /\ attempt = "uncertain" /\ target = intent
    /\ ResolveAttempt("observed")

RetryAfterObservation ==
    /\ attempt = "uncertain" /\ target = Absent /\ stage = intent
    /\ ResolveAttempt("idle")

ObserveConflict ==
    /\ target = Incumbent
    /\ ResolveAttempt("conflict")

FlushNamespaces ==
    /\ running /\ attempt = "observed" /\ ~namespaceFlushed
    /\ namespaceFlushed' = TRUE
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, receipt, running,
                   crashAvailable>>

CommitReceipt ==
    /\ running /\ attempt = "observed" /\ namespaceFlushed /\ ~receipt
    /\ receipt' = TRUE
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   running, crashAvailable>>

BeginCrash ==
    /\ running /\ crashAvailable
    /\ crashAvailable' = FALSE /\ running' = FALSE
    /\ pending' = {}
    /\ attempt' = IF intent = Absent THEN "idle" ELSE "uncertain"
    /\ IF evidence \in {"written", "sealed"}
       THEN /\ evidence' = "empty" /\ acceptedEpoch' = NoEpoch
       ELSE /\ evidence' = IF evidence = "verified" THEN "data flushed" ELSE evidence
            /\ UNCHANGED acceptedEpoch
    /\ UNCHANGED <<epoch, incumbentArrived, intent, namespaceFlushed, receipt>>

CrashKeepingRename ==
    /\ BeginCrash
    /\ UNCHANGED <<stage, target>>

CrashLosingRename ==
    /\ BeginCrash
    /\ ~namespaceFlushed /\ target \in OwnedObjects
    /\ stage' = target /\ target' = Absent

Restart ==
    /\ ~running
    /\ running' = TRUE
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, crashAvailable>>

Next ==
    \/ Prepare \/ SubmitWrite \/ ChangeSourceView
    \/ \E completion \in Epochs : AcceptWrite(completion) \/ DiscardLateWrite(completion)
    \/ Seal \/ FlushData \/ ReadBackMatch \/ ReadBackMismatch \/ FlushRequiredMetadata
    \/ PersistIntent \/ StartAttempt \/ ExternalArrival \/ ApplyNoClobber
    \/ LoseReplyBeforeEffect \/ LoseReplyAfterEffect
    \/ ObservePublished \/ ReconcilePublished \/ RetryAfterObservation \/ ObserveConflict
    \/ FlushNamespaces \/ CommitReceipt \/ CrashKeepingRename \/ CrashLosingRename \/ Restart

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ epoch \in Epochs /\ pending \subseteq Epochs
    /\ acceptedEpoch \in Epochs \cup {NoEpoch} /\ evidence \in EvidenceStates
    /\ stage \in OwnedObjects \cup {Absent} /\ target \in OwnedObjects \cup {Absent, Incumbent}
    /\ incumbentArrived \in BOOLEAN /\ intent \in OwnedObjects \cup {Absent}
    /\ attempt \in AttemptStates /\ namespaceFlushed \in BOOLEAN /\ receipt \in BOOLEAN
    /\ running \in BOOLEAN /\ crashAvailable \in BOOLEAN

IncumbentPreserved == incumbentArrived => target = Incumbent

CurrentEpochEvidence ==
    IF evidence = "empty"
    THEN acceptedEpoch = NoEpoch
    ELSE acceptedEpoch = epoch

SealedStageHasNoWriter ==
    evidence \notin {"empty", "written"} => epoch \notin pending

PriorPublicationEvidence ==
    target \in OwnedObjects =>
        /\ target = OwnedObject(epoch) /\ intent = target
        /\ evidence = "metadata flushed" /\ acceptedEpoch = epoch
        /\ epoch \notin pending

IntentPreservesOwnedObject ==
    intent # Absent =>
        /\ intent = OwnedObject(epoch)
        /\ (stage = intent) # (target = intent)

ConflictRetainsStage == attempt = "conflict" => stage = intent /\ target = Incumbent

NamespaceBarrierFollowsPublication ==
    namespaceFlushed => target = intent /\ target \in OwnedObjects

ReceiptFollowsNamespaceBarrier == receipt => namespaceFlushed

=============================================================================
