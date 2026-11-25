---------------------------- MODULE SyncBaseline ----------------------------
EXTENDS Naturals, TLC

CONSTANTS TreatUnknownAsAbsent, SkipReceipts, AllowStaleGeneration

VARIABLES subject, decision, receipts, currentGeneration, predecessor, published

vars == <<subject, decision, receipts, currentGeneration, predecessor, published>>

Files == {"A", "B", "C"}
Observations == Files \cup {"absent", "unknown", "unsupported"}
Baselines == Files \cup {"uninitialized", "common-absent", "asymmetric"}
Sides == {"left", "right"}

\* Construct the oracle by classifying each endpoint relative to the old common
\* version, then combine the relative labels by a matrix. Equal evidence has
\* its own reconciliation rule before unequal pairs enter the matrix.
Relative(old, observation) ==
    IF observation = "absent" THEN IF old \in Files THEN "deleted" ELSE "absent"
    ELSE IF old \notin Files THEN "new"
    ELSE IF old = observation THEN "unchanged"
    ELSE "edited"

RelativeStates == <<"unchanged", "new", "edited", "deleted", "absent">>
DecisionMatrix ==
    <<<<"invalid", "invalid", "right-incumbent", "deleted-right", "invalid">>,
         <<"invalid", "divergent", "invalid", "invalid", "left-absent">>,
         <<"left-incumbent", "invalid", "divergent", "edited-left", "invalid">>,
         <<"deleted-left", "invalid", "edited-right", "tombstone", "invalid">>,
         <<"invalid", "right-absent", "invalid", "invalid", "unchanged">>>>

RelativeDecision(old, left, right) ==
    IF left = right /\ left \in Files
    THEN IF old = left THEN "unchanged" ELSE "baseline-match"
    ELSE LET i == CHOOSE i \in 1..5 : RelativeStates[i] = Relative(old, left)
             j == CHOOSE j \in 1..5 : RelativeStates[j] = Relative(old, right)
         IN DecisionMatrix[i][j]

Classify(old, complete, left, right) ==
    IF ~complete THEN "incomplete"
    ELSE IF "unknown" \in {left, right} THEN "unknown"
    ELSE IF "unsupported" \in {left, right} THEN "unsupported"
    ELSE IF old = "asymmetric" THEN "asymmetric"
    ELSE RelativeDecision(old, left, right)

AdmitObservation(observation) ==
    IF TreatUnknownAsAbsent /\ observation = "unknown" THEN "absent" ELSE observation

Init ==
    /\ subject \in [old : Baselines, complete : BOOLEAN, left : Observations,
                    right : Observations]
    /\ decision = Classify(subject.old, subject.complete, AdmitObservation(subject.left),
                          AdmitObservation(subject.right))
    /\ PrintT(<<"sync-case", subject.old, subject.complete, subject.left,
                subject.right, decision>>)
    /\ receipts = [side \in Sides |-> "missing"]
    /\ currentGeneration = 1
    /\ predecessor = 0
    /\ published = FALSE

\* Stuttering leaves a missing receipt missing (including receipt loss).
\* A matching receipt binds the endpoint observation and generation 1; pair,
\* path and policy are constant throughout the model. Signed bytes, retention
\* evidence and storage effects are abstract assumptions outside this model.
ReceiptKinds == {"matching", "wrong-observation", "wrong-generation"}
Eligible == decision \in {"baseline-match", "tombstone"}
PairedReceipts == \A side \in Sides : receipts[side] = "matching"

Receive ==
    /\ ~published
    /\ Eligible
    /\ \E side \in Sides, kind \in ReceiptKinds :
        /\ receipts[side] = "missing"
        /\ receipts' = [receipts EXCEPT ![side] = kind]
    /\ UNCHANGED <<subject, decision, currentGeneration, predecessor, published>>

OtherWriterAdvances ==
    /\ ~published
    /\ currentGeneration = 1
    /\ currentGeneration' = 2
    /\ UNCHANGED <<subject, decision, receipts, predecessor, published>>

PublishBaseline ==
    /\ ~published
    /\ Eligible
    /\ (PairedReceipts \/ SkipReceipts)
    /\ (currentGeneration = 1 \/ AllowStaleGeneration)
    /\ published' = TRUE
    /\ predecessor' = currentGeneration
    /\ currentGeneration' = 2
    /\ UNCHANGED <<subject, decision, receipts>>

Next == Receive \/ OtherWriterAdvances \/ PublishBaseline
Spec == Init /\ [][Next]_vars

ClassificationIsDefined == decision # "invalid"

IncompletePreventsInference ==
    ~subject.complete => decision = "incomplete"

UnknownPreventsInference ==
    (subject.complete /\ "unknown" \in {subject.left, subject.right}) =>
        decision = "unknown"

PublicationRequiresPairedReceipts ==
    published => PairedReceipts

PublicationRequiresCurrentPredecessor ==
    published => predecessor = 1 /\ currentGeneration = predecessor + 1

PublicationIsEvidenceBound ==
    published =>
        /\ subject.complete
        /\ subject.left = subject.right
        /\ CASE decision = "baseline-match" ->
                   /\ subject.left \in Files
                   /\ subject.old # subject.left
             [] decision = "tombstone" ->
                   /\ subject.left = "absent"
                   /\ subject.old \in Files
             [] OTHER -> FALSE
=============================================================================
