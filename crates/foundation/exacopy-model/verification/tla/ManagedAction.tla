----------------------------- MODULE ManagedAction -----------------------------
EXTENDS Naturals

CONSTANT Mutation

Claimants == 1..2
NoActor == 0
ForeignReceipt == 3
Actors == 0..2
Receipts == 0..3

VARIABLES selected, process, issuer, live, uncertain, interrupted, refused,
          intent, child, observation

vars == <<selected, process, issuer, live, uncertain, interrupted, refused,
          intent, child, observation>>

Init ==
    /\ selected \in {"current", "stale"}
    /\ process = "foreground"
    /\ issuer = [owner |-> NoActor, spends |-> 0]
    /\ live = FALSE /\ uncertain = FALSE /\ interrupted = FALSE
    /\ refused = [contender |-> NoActor, restart |-> FALSE]
    /\ intent = [submitted |-> NoActor, persisted |-> NoActor, confirmed |-> NoActor]
    /\ child = [creates |-> 0, attempt |-> NoActor, startedWith |-> NoActor,
                 job |-> "none", result |-> "none"]
    /\ observation = [submitted |-> NoActor, persisted |-> NoActor,
                       reread |-> NoActor, confirmed |-> NoActor]

Held == process = "foreground" /\ live /\ ~uncertain /\ issuer.owner # NoActor

\* An independent issuer atomically and durably spends the selected activation.
\* The ordinary prepared segment is not its authoritative spend record.
Claim ==
    /\ selected = "current" /\ issuer.spends < 2
    /\ intent.persisted = NoActor
    /\ ( (process = "foreground" /\ issuer.spends = 0 /\ ~uncertain)
        \/ (Mutation = "trust-pristine" /\ process = "reopened" /\ interrupted))
    /\ \E actor \in Claimants :
        /\ (issuer.spends = 0 \/ actor # issuer.owner)
        /\ issuer' = [owner |-> actor, spends |-> issuer.spends + 1]
    /\ live' = TRUE
    /\ UNCHANGED <<selected, process, uncertain, interrupted, refused,
                   intent, child, observation>>

SubmitIntent ==
    /\ Held /\ intent.submitted = NoActor
    /\ intent' = [intent EXCEPT !.submitted = issuer.owner]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   child, observation>>

PersistIntent ==
    /\ process = "foreground" /\ ~uncertain
    /\ intent.submitted # NoActor /\ intent.persisted = NoActor
    /\ intent' = [intent EXCEPT !.persisted = intent.submitted]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   child, observation>>

InterruptIntent ==
    /\ process = "foreground" /\ ~uncertain
    /\ intent.submitted # NoActor /\ intent.persisted = NoActor
    /\ uncertain' = TRUE /\ interrupted' = TRUE
    /\ UNCHANGED <<selected, process, issuer, live, refused, intent, child, observation>>

ConfirmIntent ==
    /\ process = "foreground" /\ ~uncertain
    /\ intent.persisted = issuer.owner /\ issuer.owner # NoActor
    /\ intent.confirmed = NoActor
    /\ intent' = [intent EXCEPT !.confirmed = intent.persisted]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   child, observation>>

CreateChildJob ==
    /\ Held
    /\ intent.persisted = issuer.owner
    /\ (intent.confirmed = issuer.owner \/ Mutation = "early-create")
    /\ (child.creates = 0
        \/ (Mutation = "duplicate-create" /\ child.creates = 1 /\ child.job = "pending"))
    /\ child' = [child EXCEPT !.creates = @ + 1, !.attempt = issuer.owner,
                             !.startedWith = intent.confirmed, !.job = "pending"]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, observation>>

ObserveCreatedJob ==
    /\ process = "foreground" /\ ~uncertain /\ child.job = "pending"
    /\ child' = [child EXCEPT !.job = "created"]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, observation>>

FailChildCreation ==
    /\ process = "foreground" /\ ~uncertain /\ child.job = "pending"
    /\ \E result \in {"not-created", "private-unconfirmed"} :
        /\ child' = [child EXCEPT !.job = result]
        /\ uncertain' = (result = "private-unconfirmed")
    /\ UNCHANGED <<selected, process, issuer, live, interrupted, refused,
                   intent, observation>>

SubmitChildRename ==
    /\ Held /\ child.job = "created" /\ child.result = "none"
    /\ child' = [child EXCEPT !.result = "pending"]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, observation>>

SettleVerified ==
    /\ Held /\ child.result = "pending"
    /\ child' = [child EXCEPT !.result = "verified"]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, observation>>

SettleConflict ==
    /\ process = "foreground" /\ child.result = "pending"
    /\ child' = [child EXCEPT !.result = "conflict"]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, observation>>

SettleUnknown ==
    /\ process = "foreground" /\ child.result = "pending"
    /\ child' = [child EXCEPT !.result = "unknown"]
    /\ uncertain' = TRUE
    /\ UNCHANGED <<selected, process, issuer, live, interrupted, refused,
                   intent, observation>>

SettleIncomplete ==
    /\ process = "foreground" /\ child.result = "pending"
    /\ child' = [child EXCEPT !.result = "published-incomplete"]
    /\ uncertain' = TRUE
    /\ UNCHANGED <<selected, process, issuer, live, interrupted, refused,
                   intent, observation>>

\* These are independently verified v2 terminal projections. The foreign one
\* is valid on its own but is unrelated to the live parent intent.
SubmitObservation ==
    /\ Held /\ child.result = "verified" /\ observation.submitted = NoActor
    /\ \E receipt \in {child.attempt, ForeignReceipt} :
        /\ (receipt = child.attempt \/ Mutation = "foreign-receipt")
        /\ observation' = [observation EXCEPT !.submitted = receipt]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, child>>

PersistObservation ==
    /\ process = "foreground" /\ ~uncertain
    /\ observation.submitted # NoActor /\ observation.persisted = NoActor
    /\ observation' = [observation EXCEPT !.persisted = observation.submitted]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, child>>

InterruptObservation ==
    /\ process = "foreground" /\ ~uncertain
    /\ observation.submitted # NoActor /\ observation.confirmed = NoActor
    /\ uncertain' = TRUE
    /\ UNCHANGED <<selected, process, issuer, live, interrupted, refused,
                   intent, child, observation>>

ReadbackObservation ==
    /\ process = "foreground" /\ ~uncertain
    /\ observation.persisted # NoActor /\ observation.reread = NoActor
    /\ observation' = [observation EXCEPT !.reread = observation.persisted]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, child>>

ConfirmObservation ==
    /\ process = "foreground" /\ ~uncertain
    /\ observation.submitted # NoActor /\ observation.confirmed = NoActor
    /\ (observation.reread = observation.submitted \/ Mutation = "early-association")
    /\ observation' = [observation EXCEPT !.confirmed = observation.submitted]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted, refused,
                   intent, child>>

Withdraw ==
    /\ process = "foreground" /\ live
    /\ live' = FALSE
    /\ UNCHANGED <<selected, process, issuer, uncertain, interrupted, refused,
                   intent, child, observation>>

Crash ==
    /\ process = "foreground"
    /\ process' = "down" /\ live' = FALSE
    /\ uncertain' = (uncertain \/ (issuer.spends # 0 /\ observation.confirmed = NoActor))
    /\ UNCHANGED <<selected, issuer, interrupted, refused, intent, child, observation>>

Reopen ==
    /\ process = "down" /\ process' = "reopened"
    /\ UNCHANGED <<selected, issuer, live, uncertain, interrupted, refused,
                   intent, child, observation>>

RefuseSpentActivation ==
    /\ process = "reopened" /\ issuer.spends = 1
    /\ interrupted /\ intent.persisted = NoActor /\ ~refused.restart
    /\ refused' = [refused EXCEPT !.restart = TRUE]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted,
                   intent, child, observation>>

RefuseCompetingActivation ==
    /\ Held /\ refused.contender = NoActor
    /\ \E actor \in Claimants :
        /\ actor # issuer.owner
        /\ refused' = [refused EXCEPT !.contender = actor]
    /\ UNCHANGED <<selected, process, issuer, live, uncertain, interrupted,
                   intent, child, observation>>

Next ==
    \/ Claim \/ SubmitIntent \/ PersistIntent \/ InterruptIntent \/ ConfirmIntent
    \/ CreateChildJob \/ ObserveCreatedJob \/ FailChildCreation \/ SubmitChildRename
    \/ SettleVerified \/ SettleConflict \/ SettleUnknown \/ SettleIncomplete
    \/ SubmitObservation \/ PersistObservation \/ InterruptObservation
    \/ ReadbackObservation \/ ConfirmObservation
    \/ Withdraw \/ Crash \/ Reopen \/ RefuseSpentActivation \/ RefuseCompetingActivation

Spec == Init /\ [][Next]_vars

Types ==
    /\ selected \in {"current", "stale"}
    /\ process \in {"foreground", "down", "reopened"}
    /\ issuer \in [owner : Actors, spends : 0..2]
    /\ live \in BOOLEAN /\ uncertain \in BOOLEAN /\ interrupted \in BOOLEAN
    /\ refused \in [contender : Actors, restart : BOOLEAN]
    /\ intent \in [submitted : Actors, persisted : Actors, confirmed : Actors]
    /\ child \in [creates : 0..2, attempt : Actors, startedWith : Actors,
                    job : {"none", "pending", "created", "not-created", "private-unconfirmed"},
                    result : {"none", "pending", "verified", "conflict", "unknown",
                              "published-incomplete"}]
    /\ observation \in [submitted : Receipts, persisted : Receipts,
                          reread : Receipts, confirmed : Receipts]

AtMostOneActivation == issuer.spends <= 1
AtMostOneChildCreation == child.creates <= 1
CreateRequiresConfirmedIntent ==
    child.creates # 0 => child.startedWith = child.attempt /\ child.attempt # NoActor
AssociationRequiresBoundReceipt ==
    observation.submitted # NoActor =>
        observation.submitted = child.attempt /\ child.attempt = child.startedWith
        /\ child.result = "verified"
AssociationRequiresConfirmedEvidence ==
    observation.confirmed # NoActor =>
        observation.confirmed = observation.persisted /\ observation.confirmed = observation.reread

UncertainCannotAssociate == uncertain => observation.confirmed = NoActor
InterruptedIntentCannotAuthorizeChild ==
    interrupted => intent.persisted = NoActor /\ intent.confirmed = NoActor /\ child.creates = 0

=============================================================================
