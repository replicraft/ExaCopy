-------------------------- MODULE WitnessNamespace --------------------------
EXTENDS Naturals, FiniteSets

CONSTANT Mutation

Slots == 1..2
Names == {"stage", "witness", "target", "extra"}
HeldNames == {"stage", "witness", "target"}
Kinds == {"origin", "unused", "external"}
Phases == {"capture", "witness-intent", "sealed", "rename-intent",
           "live-published", "recovered", "conflict", "uncertain"}
Processes == {"live", "down", "reopened"}
Replies == {"none", "success", "conflict", "unknown"}

VARIABLES ns, refs, owners, phase, process, grant, consent, reply,
          submissions, postCrashSubmission, observed, inspection

vars == <<ns, refs, owners, phase, process, grant, consent, reply,
          submissions, postCrashSubmission, observed, inspection>>

Absent == 0
Origin == 1
NoObservation == [target |-> FALSE, original |-> FALSE, exact |-> FALSE]
Authorized == grant /\ consent
LinkCount(slot) == Cardinality({name \in Names : ns[name] = slot})
Holds(name) == ns[name] # Absent /\ refs[name] = ns[name]

ExactBeforeRename ==
    /\ Holds("stage") /\ Holds("witness")
    /\ ns.stage = Origin /\ ns.witness = ns.stage
    /\ LinkCount(Origin) = 2

ExactAfterRename ==
    /\ Holds("witness") /\ Holds("target")
    /\ ns.witness = Origin /\ ns.target = ns.witness
    /\ ns.stage = Absent /\ LinkCount(Origin) = 2

Snapshot ==
    [target |-> Holds("target"),
     original |-> IF ns.target = Absent THEN FALSE ELSE owners[ns.target] = "origin",
     exact |-> ExactAfterRename]

Allocatable(slot) ==
    /\ \A name \in HeldNames : refs[name] # slot
    /\ \A name \in Names :
        ns[name] # slot \/ (Mutation = "reuse-witnessed" /\ name = "witness")

Init ==
    /\ ns = [stage |-> Origin, witness |-> Absent, target |-> Absent, extra |-> Absent]
    /\ refs = [stage |-> Origin, witness |-> Absent, target |-> Absent]
    /\ owners = [i \in Slots |-> IF i = Origin THEN "origin" ELSE "unused"]
    /\ phase = "capture" /\ process = "live"
    /\ grant = TRUE /\ consent = TRUE /\ reply = "none"
    /\ submissions = 0 /\ postCrashSubmission = FALSE
    /\ observed = NoObservation /\ inspection = TRUE

RecordWitnessIntent ==
    /\ process = "live" /\ phase = "capture" /\ Authorized
    /\ Holds("stage") /\ LinkCount(Origin) = 1 /\ ns.witness = Absent
    /\ phase' = "witness-intent"
    /\ UNCHANGED <<ns, refs, owners, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

LinkWitness ==
    /\ process = "live" /\ phase = "witness-intent" /\ Authorized
    /\ Holds("stage") /\ ns.stage = Origin /\ LinkCount(Origin) = 1
    /\ ns.witness = Absent
    /\ ns' = [ns EXCEPT !.witness = refs.stage]
    /\ refs' = [refs EXCEPT !.witness = refs.stage]
    /\ UNCHANGED <<owners, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

ConfirmWitness ==
    /\ process = "live" /\ phase = "witness-intent" /\ Authorized
    /\ ExactBeforeRename /\ inspection
    /\ phase' = "sealed"
    /\ UNCHANGED <<ns, refs, owners, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

RecordRenameIntent ==
    /\ process = "live" /\ phase = "sealed" /\ Authorized
    /\ ExactBeforeRename /\ inspection /\ ns.target = Absent
    /\ phase' = "rename-intent"
    /\ UNCHANGED <<ns, refs, owners, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

SubmitRename(loseReply) ==
    /\ phase = "rename-intent" /\ Authorized /\ submissions < 2
    /\ ( (process = "live" /\ submissions = 0)
        \/ (Mutation = "revive-rename" /\ process = "reopened"))
    /\ ExactBeforeRename /\ inspection
    /\ LET succeeded == ns.target = Absent IN
        /\ ns' = IF succeeded THEN [ns EXCEPT !.stage = Absent, !.target = ns.stage] ELSE ns
        /\ refs' = IF succeeded THEN [refs EXCEPT !.target = refs.stage] ELSE refs
        /\ reply' = IF loseReply THEN "unknown" ELSE IF succeeded THEN "success" ELSE "conflict"
    /\ submissions' = submissions + 1
    /\ postCrashSubmission' = (postCrashSubmission \/ process # "live")
    /\ UNCHANGED <<owners, phase, process, grant, consent, observed, inspection>>

RecordLiveFact ==
    /\ process = "live" /\ phase = "rename-intent"
    /\ reply # "none"
    /\ phase' = CASE reply = "success" /\ ExactAfterRename /\ inspection -> "live-published"
                   [] reply = "conflict" /\ ExactBeforeRename /\ Holds("target") /\ inspection -> "conflict"
                   [] OTHER -> "uncertain"
    /\ observed' = IF phase' = "live-published" THEN Snapshot ELSE observed
    /\ UNCHANGED <<ns, refs, owners, process, grant, consent, reply,
                   submissions, postCrashSubmission, inspection>>

SuccessfulObservation == reply = "success" /\ ExactAfterRename /\ inspection

RecordExpiredSuccess ==
    /\ ~Authorized /\ SuccessfulObservation /\ RecordLiveFact

RecordExpiredOther ==
    /\ ~Authorized /\ ~SuccessfulObservation /\ RecordLiveFact

RecoverPublished ==
    /\ process = "reopened" /\ phase = "rename-intent" /\ Authorized
    /\ inspection
    /\ (ExactAfterRename
        \/ (Mutation = "witness-alone" /\ Holds("witness") /\ ns.stage = Absent
            /\ ns.target = Absent)
        \/ (Mutation = "stale-target" /\ Holds("witness") /\ ns.stage = Absent
            /\ refs.target = ns.witness))
    /\ phase' = "recovered"
    /\ observed' = Snapshot
    /\ UNCHANGED <<ns, refs, owners, process, grant, consent, reply,
                   submissions, postCrashSubmission, inspection>>

Crash ==
    /\ process = "live"
    /\ process' = "down" /\ refs' = [name \in HeldNames |-> Absent]
    /\ reply' = "none"
    /\ UNCHANGED <<ns, owners, phase, grant, consent, submissions,
                   postCrashSubmission, observed, inspection>>

Reopen ==
    /\ process = "down" /\ process' = "reopened"
    /\ UNCHANGED <<ns, refs, owners, phase, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

HoldName(name) ==
    /\ process # "down" /\ ns[name] # Absent /\ refs[name] # ns[name]
    /\ refs' = [refs EXCEPT ![name] = ns[name]]
    /\ UNCHANGED <<ns, owners, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

ReleaseName(name) ==
    /\ refs[name] # Absent
    /\ refs' = [refs EXCEPT ![name] = Absent]
    /\ UNCHANGED <<ns, owners, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

ExternalCreate(slot) ==
    /\ ns.target = Absent /\ Allocatable(slot)
    /\ ns' = [ns EXCEPT !.target = slot]
    /\ owners' = [owners EXCEPT ![slot] = "external"]
    /\ UNCHANGED <<refs, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

ExternalUnlink ==
    /\ ns.target # Absent
    /\ ns' = [ns EXCEPT !.target = Absent]
    /\ UNCHANGED <<refs, owners, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

ExternalExtraAlias ==
    /\ ns.target # Absent /\ ns.extra = Absent
    /\ ns' = [ns EXCEPT !.extra = ns.target]
    /\ UNCHANGED <<refs, owners, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

FinishInspection ==
    /\ ~inspection /\ inspection' = TRUE
    /\ UNCHANGED <<ns, refs, owners, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed>>

LoseInspection ==
    /\ inspection /\ inspection' = FALSE
    /\ UNCHANGED <<ns, refs, owners, phase, process, grant, consent, reply,
                   submissions, postCrashSubmission, observed>>

ExpireGrant ==
    /\ grant /\ grant' = FALSE
    /\ UNCHANGED <<ns, refs, owners, phase, process, consent, reply,
                   submissions, postCrashSubmission, observed, inspection>>

ExpireConsent ==
    /\ consent /\ consent' = FALSE
    /\ UNCHANGED <<ns, refs, owners, phase, process, grant, reply,
                   submissions, postCrashSubmission, observed, inspection>>

Next ==
    \/ RecordWitnessIntent \/ LinkWitness \/ ConfirmWitness \/ RecordRenameIntent
    \/ \E lost \in BOOLEAN : SubmitRename(lost)
    \/ (Authorized /\ RecordLiveFact)
    \/ RecordExpiredSuccess \/ RecordExpiredOther \/ RecoverPublished
    \/ Crash \/ Reopen
    \/ \E name \in HeldNames : HoldName(name) \/ ReleaseName(name)
    \/ \E slot \in Slots : ExternalCreate(slot)
    \/ ExternalUnlink \/ ExternalExtraAlias \/ FinishInspection \/ LoseInspection
    \/ ExpireGrant \/ ExpireConsent

Spec == Init /\ [][Next]_vars

Types ==
    /\ ns \in [Names -> Slots \cup {Absent}] /\ refs \in [HeldNames -> Slots \cup {Absent}]
    /\ owners \in [Slots -> Kinds] /\ phase \in Phases /\ process \in Processes
    /\ grant \in BOOLEAN /\ consent \in BOOLEAN /\ reply \in Replies
    /\ submissions \in 0..2 /\ postCrashSubmission \in BOOLEAN /\ inspection \in BOOLEAN
    /\ observed \in [target: BOOLEAN, original: BOOLEAN, exact: BOOLEAN]

WitnessPreservesOrigin ==
    ns.witness = Absent \/ owners[ns.witness] = "origin"

RecoveryRequiresPresentTarget ==
    phase # "recovered" \/ (observed.target /\ observed.original /\ observed.exact)

AtMostOneLiveSubmission ==
    submissions <= 1 /\ ~postCrashSubmission

=============================================================================
