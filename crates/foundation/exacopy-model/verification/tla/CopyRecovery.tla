--------------------------- MODULE CopyRecovery ---------------------------

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS AllowEarlyPublication, AllowUnverifiedRetry

InitialEpoch == "initial view"
NextEpoch == "changed view"
RecoveryEpoch == "recovery"
WriteEpochs == {InitialEpoch, NextEpoch}
Epochs == WriteEpochs \cup {RecoveryEpoch}
NoEpoch == "no epoch"
Absent == <<"absent", NoEpoch>>
Incumbent == <<"incumbent", NoEpoch>>
OwnedObject(epoch) == <<"owned stage", epoch>>
OwnedObjects == {OwnedObject(epoch) : epoch \in WriteEpochs}

EvidenceStates == {"empty", "retained", "written", "quiesced", "data flushed",
                   "verified", "mismatch", "metadata flushed", "sealed"}
AttemptStates == {"idle", "in flight", "uncertain", "observed", "conflict"}

VARIABLES epoch, pending, acceptedEpoch, evidence, stage, target,
          incumbentArrived, intent, attempt, namespaceFlushed, receipt,
          running, crashAvailable, issued

vars == <<epoch, pending, acceptedEpoch, evidence, stage, target,
          incumbentArrived, intent, attempt, namespaceFlushed, receipt,
          running, crashAvailable, issued>>

StageMatchesEpoch(object) ==
    IF epoch = RecoveryEpoch THEN object \in OwnedObjects
    ELSE object = OwnedObject(epoch)

IssuedEpochs == {issued[i] : i \in 1..Len(issued)}

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
    /\ issued = <<>>

Prepare ==
    /\ running /\ epoch \in WriteEpochs /\ stage = Absent /\ target \notin OwnedObjects
    /\ stage' = OwnedObject(epoch)
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable, issued>>

SubmitWrite ==
    /\ running /\ epoch \in WriteEpochs /\ stage = OwnedObject(epoch) /\ evidence = "empty"
    /\ epoch \notin pending
    /\ pending' = pending \cup {epoch}
    /\ UNCHANGED <<epoch, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable, issued>>

AcceptWrite(epochOfCompletion) ==
    /\ running /\ epochOfCompletion \in pending
    /\ epochOfCompletion = epoch /\ stage = OwnedObject(epoch)
    /\ evidence = "empty"
    /\ pending' = pending \ {epochOfCompletion}
    /\ acceptedEpoch' = epochOfCompletion
    /\ evidence' = "written"
    /\ UNCHANGED <<epoch, stage, target, incumbentArrived, intent, attempt,
                   namespaceFlushed, receipt, running, crashAvailable, issued>>

DiscardLateWrite(epochOfCompletion) ==
    /\ running /\ epochOfCompletion \in pending /\ epochOfCompletion # epoch
    /\ pending' = pending \ {epochOfCompletion}
    /\ UNCHANGED <<epoch, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable, issued>>

ChangeSourceView ==
    /\ running /\ epoch = InitialEpoch /\ stage = OwnedObject(epoch)
    /\ intent = Absent /\ attempt = "idle"
    \* The old stage is retained outside the active stage slot.
    /\ epoch' = NextEpoch
    /\ stage' = OwnedObject(NextEpoch)
    /\ evidence' = "empty"
    /\ acceptedEpoch' = NoEpoch
    /\ UNCHANGED <<pending, target, incumbentArrived, intent, attempt,
                   namespaceFlushed, receipt, running, crashAvailable, issued>>

AdvanceEvidence(from, to) ==
    /\ running /\ StageMatchesEpoch(stage) /\ evidence = from
    /\ evidence' = to
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   receipt, running, crashAvailable, issued>>

JoinWriters == /\ epoch \notin pending
               /\ AdvanceEvidence("written", "quiesced")
FlushData == AdvanceEvidence("quiesced", "data flushed")
ReadBackMatch == AdvanceEvidence("data flushed", "verified")
ReadBackMismatch == AdvanceEvidence("data flushed", "mismatch")
FlushRequiredMetadata == AdvanceEvidence("verified", "metadata flushed")
Seal == AdvanceEvidence("metadata flushed", "sealed")

PersistIntent ==
    /\ running /\ intent = Absent /\ StageMatchesEpoch(stage)
    /\ (evidence = "sealed"
        \/ (AllowUnverifiedRetry /\ epoch = RecoveryEpoch /\ evidence = "retained"))
    /\ intent' = stage
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, attempt, namespaceFlushed, receipt,
                   running, crashAvailable, issued>>

StartAttempt ==
    /\ running /\ attempt = "idle" /\ StageMatchesEpoch(stage)
    /\ epoch \notin IssuedEpochs
    /\ AllowEarlyPublication \/ intent = stage
    /\ attempt' = "in flight"
    /\ issued' = Append(issued, epoch)
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, namespaceFlushed, receipt,
                   running, crashAvailable>>

ExternalArrival ==
    /\ target = Absent /\ ~incumbentArrived
    /\ target' = Incumbent /\ incumbentArrived' = TRUE
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, intent,
                   attempt, namespaceFlushed, receipt, running, crashAvailable, issued>>

NoClobberEffect ==
    /\ running /\ attempt = "in flight" /\ StageMatchesEpoch(stage)
    \* The same atomic move applies to normal and mutant configurations.
    /\ target = Absent
    /\ stage' = Absent /\ target' = stage
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, incumbentArrived,
                   intent, attempt, namespaceFlushed, receipt, running,
                   crashAvailable, issued>>

ApplyNoClobber ==
    /\ epoch \in WriteEpochs
    /\ NoClobberEffect

ApplyRetainedStageNoClobber ==
    /\ epoch = RecoveryEpoch
    /\ NoClobberEffect

LoseReply ==
    /\ running /\ attempt = "in flight"
    /\ attempt' = "uncertain"
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, namespaceFlushed, receipt,
                   running, crashAvailable, issued>>

LoseReplyBeforeEffect == /\ stage # Absent /\ LoseReply
LoseReplyAfterEffect == /\ target \in OwnedObjects /\ LoseReply

ResolveAttempt(result) ==
    /\ running /\ attempt \in {"in flight", "uncertain"}
    /\ StageMatchesEpoch(intent) /\ evidence = "sealed"
    /\ attempt' = result
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, namespaceFlushed, receipt,
                   running, crashAvailable, issued>>

ObservePublished ==
    /\ attempt = "in flight" /\ target = intent
    /\ ResolveAttempt("observed")

ReconcilePublished ==
    /\ attempt = "uncertain" /\ target = intent
    /\ ResolveAttempt("observed")

RebindRetainedStage ==
    /\ running /\ epoch \in WriteEpochs /\ attempt = "uncertain"
    /\ target = Absent /\ StageMatchesEpoch(stage) /\ stage = intent
    /\ evidence = "sealed"
    \* The owned object is unchanged. The retained intent confers no authority
    \* in the new epoch, which needs fresh observations and its own intent.
    /\ epoch' = RecoveryEpoch /\ intent' = Absent /\ attempt' = "idle"
    /\ evidence' = "retained" /\ acceptedEpoch' = NoEpoch
    /\ UNCHANGED <<pending, stage, target, incumbentArrived, namespaceFlushed,
                   receipt, running, crashAvailable, issued>>

RetryAfterObservation ==
    /\ crashAvailable
    /\ RebindRetainedStage

RetryAfterCrash ==
    /\ ~crashAvailable
    /\ RebindRetainedStage

QuiesceRetainedStage ==
    /\ running /\ epoch = RecoveryEpoch /\ StageMatchesEpoch(stage)
    /\ evidence = "retained" /\ stage[2] \notin pending
    /\ evidence' = "quiesced" /\ acceptedEpoch' = epoch
    /\ UNCHANGED <<epoch, pending, stage, target, incumbentArrived, intent, attempt,
                   namespaceFlushed, receipt, running, crashAvailable, issued>>

ObserveConflict ==
    /\ epoch \in WriteEpochs /\ target = Incumbent
    /\ ResolveAttempt("conflict")

ObserveRetainedStageConflict ==
    /\ epoch = RecoveryEpoch /\ target = Incumbent
    /\ ResolveAttempt("conflict")

FlushNamespaces ==
    /\ running /\ attempt = "observed" /\ ~namespaceFlushed
    /\ namespaceFlushed' = TRUE
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, receipt, running,
                   crashAvailable, issued>>

CommitReceipt ==
    /\ running /\ attempt = "observed" /\ namespaceFlushed /\ ~receipt
    /\ receipt' = TRUE
    /\ UNCHANGED <<epoch, pending, acceptedEpoch, evidence, stage, target,
                   incumbentArrived, intent, attempt, namespaceFlushed,
                   running, crashAvailable, issued>>

BeginCrash ==
    /\ running /\ crashAvailable
    /\ crashAvailable' = FALSE /\ running' = FALSE
    /\ pending' = {}
    /\ attempt' = IF intent = Absent THEN "idle" ELSE "uncertain"
    /\ IF epoch = RecoveryEpoch /\ intent = Absent /\ evidence # "mismatch"
       THEN /\ evidence' = "retained" /\ acceptedEpoch' = NoEpoch
       ELSE IF evidence \in {"written", "quiesced"}
            THEN /\ evidence' = "empty" /\ acceptedEpoch' = NoEpoch
            ELSE /\ evidence' = IF evidence = "verified" THEN "data flushed" ELSE evidence
                 /\ UNCHANGED acceptedEpoch
    /\ UNCHANGED <<epoch, incumbentArrived, intent, namespaceFlushed, receipt, issued>>

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
                   receipt, crashAvailable, issued>>

Next ==
    \/ Prepare \/ SubmitWrite \/ ChangeSourceView
    \/ \E completion \in WriteEpochs : AcceptWrite(completion) \/ DiscardLateWrite(completion)
    \/ JoinWriters \/ FlushData \/ ReadBackMatch \/ ReadBackMismatch \/ FlushRequiredMetadata \/ Seal
    \/ PersistIntent \/ StartAttempt \/ ExternalArrival \/ ApplyNoClobber
    \/ QuiesceRetainedStage \/ ApplyRetainedStageNoClobber
    \/ LoseReplyBeforeEffect \/ LoseReplyAfterEffect
    \/ ObservePublished \/ ReconcilePublished \/ ObserveConflict
    \/ RetryAfterObservation \/ RetryAfterCrash
    \/ ObserveRetainedStageConflict \/ FlushNamespaces \/ CommitReceipt \/ CrashKeepingRename \/ CrashLosingRename \/ Restart

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ epoch \in Epochs /\ pending \subseteq WriteEpochs
    /\ acceptedEpoch \in Epochs \cup {NoEpoch} /\ evidence \in EvidenceStates
    /\ stage \in OwnedObjects \cup {Absent} /\ target \in OwnedObjects \cup {Absent, Incumbent}
    /\ incumbentArrived \in BOOLEAN /\ intent \in OwnedObjects \cup {Absent}
    /\ attempt \in AttemptStates /\ namespaceFlushed \in BOOLEAN /\ receipt \in BOOLEAN
    /\ running \in BOOLEAN /\ crashAvailable \in BOOLEAN
    /\ IssuedEpochs \subseteq Epochs

IncumbentPreserved == incumbentArrived => target = Incumbent

CurrentEpochEvidence ==
    IF evidence \in {"empty", "retained"}
    THEN acceptedEpoch = NoEpoch
    ELSE acceptedEpoch = epoch

SealedStageHasNoWriter ==
    evidence \notin {"empty", "retained", "written"} =>
        (IF stage # Absent THEN stage[2] ELSE target[2]) \notin pending

PriorPublicationEvidence ==
    target \in OwnedObjects =>
        /\ StageMatchesEpoch(target) /\ intent = target /\ epoch \in IssuedEpochs
        /\ evidence = "sealed" /\ acceptedEpoch = epoch
        /\ target[2] \notin pending

IntentPreservesOwnedObject ==
    intent # Absent =>
        /\ StageMatchesEpoch(intent)
        /\ (stage = intent) # (target = intent)

AtMostOneEffectPerEpoch == Len(issued) = Cardinality(IssuedEpochs)

ConflictRetainsStage == attempt = "conflict" => stage = intent /\ target = Incumbent

NamespaceBarrierFollowsPublication ==
    namespaceFlushed => target = intent /\ target \in OwnedObjects

ReceiptFollowsNamespaceBarrier == receipt => namespaceFlushed

=============================================================================
