---------------------- MODULE PublicationBuildRetirement ----------------------
EXTENDS TLC

CONSTANT Mode, Mutation

VARIABLE s

Modes == {"strict", "prepare"}
Mutations == {
    "none", "strict-stop", "foreign-job", "ignore-root", "ignore-stop",
    "ignore-stdout", "clear-timeout", "late-request", "trust-root-output",
    "skip-image", "stale-launch"
}
Assumption == Mode \in Modes /\ Mutation \in Mutations
ASSUME Assumption

Phases == {
    "running", "retirement-issued", "stop-observed", "drain-observed",
    "quiesced", "output-checked", "image-checked", "prepared", "launched", "failed"
}
RootResults == {"none", "zero", "nonzero", "unknown"}
Binding == {"own", "foreign"}
StopResults == {"none", "success", "failure", "unknown"}
CheckResults == {"none", "verified", "refused", "uncertain"}

Init ==
    s = [
        phase       |-> "running",
        root        |-> "none",
        rootBinding |-> "foreign",
        jobBinding  |-> "foreign",
        everIssued  |-> FALSE,
        issuedLate  |-> FALSE,
        stop        |-> "none",
        stopBinding |-> "foreign",
        activeZero  |-> FALSE,
        stdoutEof   |-> FALSE,
        stderrEof   |-> FALSE,
        sinksKnown  |-> FALSE,
        expired     |-> FALSE,
        timedOut    |-> FALSE,
        transcript  |-> "none",
        heldImage   |-> "none",
        launchCheck |-> "none"
    ]

ObserveRoot(result, who) ==
    /\ s.phase = "running"
    /\ s.root = "none"
    /\ s' = [s EXCEPT !.root = result, !.rootBinding = who]

RequestRetirement(whichJob) ==
    /\ s.phase = "running"
    /\ ~s.everIssued
    /\ (Mode = "prepare" \/ Mutation = "strict-stop")
    /\ (whichJob = "own" \/ Mutation = "foreign-job")
    /\ ((s.root = "zero" /\ s.rootBinding = "own") \/ Mutation = "ignore-root")
    /\ (~s.expired \/ Mutation = "late-request")
    /\ s' = [s EXCEPT
        !.phase = "retirement-issued",
        !.jobBinding = whichJob,
        !.everIssued = TRUE,
        !.issuedLate = s.expired
    ]

ObserveStop(result, who) ==
    /\ s.phase = "retirement-issued"
    /\ s' = [s EXCEPT !.phase = "stop-observed", !.stop = result, !.stopBinding = who]

ObserveDrain(zero, stdoutEnd, stderrEnd, extents) ==
    /\ s.phase = "stop-observed"
    /\ s' = [s EXCEPT
        !.phase = "drain-observed",
        !.activeZero = zero,
        !.stdoutEof = stdoutEnd,
        !.stderrEof = stderrEnd,
        !.sinksKnown = extents
    ]

Expire ==
    /\ s.phase \in {"running", "retirement-issued", "stop-observed", "drain-observed"}
    /\ ~s.expired
    /\ s' = [s EXCEPT
        !.phase = IF Mutation \in {"clear-timeout", "late-request"} THEN s.phase ELSE "failed",
        !.expired = TRUE,
        !.timedOut = TRUE
    ]

Fail ==
    /\ s.phase \notin {"failed", "launched"}
    /\ s' = [s EXCEPT !.phase = "failed"]

ClassifyQuiesced ==
    /\ s.phase = "drain-observed"
    /\ ((s.stop = "success" /\ s.stopBinding = "own") \/ Mutation = "ignore-stop")
    /\ s.activeZero
    /\ s.stderrEof
    /\ s.sinksKnown
    /\ (s.stdoutEof \/ Mutation = "ignore-stdout")
    /\ (~s.expired \/ Mutation = "clear-timeout")
    /\ s' = [s EXCEPT
        !.phase = "quiesced",
        !.timedOut = IF Mutation = "clear-timeout" THEN FALSE ELSE s.timedOut
    ]

CheckTranscript(result) ==
    /\ s.phase = "quiesced"
    /\ s' = [s EXCEPT !.phase = "output-checked", !.transcript = result]

CheckHeldImage(result) ==
    /\ s.phase = "output-checked"
    /\ (s.transcript = "verified" \/ Mutation = "trust-root-output")
    /\ s' = [s EXCEPT !.phase = "image-checked", !.heldImage = result]

IssuePreparedImage ==
    /\ s.phase = "image-checked"
    /\ (s.heldImage = "verified" \/ Mutation = "skip-image")
    /\ s' = [s EXCEPT !.phase = "prepared"]

IssueFirstSelector(recheck) ==
    /\ s.phase = "prepared"
    /\ (recheck = "verified" \/ Mutation = "stale-launch")
    /\ s' = [s EXCEPT !.phase = "launched", !.launchCheck = recheck]

Next ==
    \/ \E r \in RootResults \ {"none"}, b \in Binding : ObserveRoot(r, b)
    \/ \E b \in Binding : RequestRetirement(b)
    \/ \E r \in StopResults \ {"none"}, b \in Binding : ObserveStop(r, b)
    \/ \E z, o, e, sKnown \in BOOLEAN : ObserveDrain(z, o, e, sKnown)
    \/ Expire
    \/ Fail
    \/ ClassifyQuiesced
    \/ \E r \in CheckResults \ {"none"} : CheckTranscript(r)
    \/ \E r \in CheckResults \ {"none"} : CheckHeldImage(r)
    \/ IssuePreparedImage
    \/ \E r \in CheckResults \ {"none"} : IssueFirstSelector(r)

Spec == Init /\ [][Next]_s

TypeOK ==
    s \in [
        phase: Phases,
        root: RootResults,
        rootBinding: Binding,
        jobBinding: Binding,
        everIssued: BOOLEAN,
        issuedLate: BOOLEAN,
        stop: StopResults,
        stopBinding: Binding,
        activeZero: BOOLEAN,
        stdoutEof: BOOLEAN,
        stderrEof: BOOLEAN,
        sinksKnown: BOOLEAN,
        expired: BOOLEAN,
        timedOut: BOOLEAN,
        transcript: CheckResults,
        heldImage: CheckResults,
        launchCheck: CheckResults
    ]

OwnedRetirementOnly ==
    s.everIssued =>
        /\ Mode = "prepare"
        /\ s.jobBinding = "own"
        /\ s.root = "zero"
        /\ s.rootBinding = "own"
        /\ ~s.issuedLate

TimeoutIsMonotone == s.expired => s.timedOut

QuiescenceIsObserved ==
    s.phase \in {"quiesced", "output-checked", "image-checked", "prepared", "launched"} =>
        /\ s.everIssued
        /\ ~s.expired
        /\ ~s.timedOut
        /\ s.stop = "success"
        /\ s.stopBinding = "own"
        /\ s.activeZero
        /\ s.stdoutEof
        /\ s.stderrEof
        /\ s.sinksKnown

PreparedImageIsAdmitted ==
    s.phase \in {"prepared", "launched"} =>
        /\ s.transcript = "verified"
        /\ s.heldImage = "verified"

FirstSelectorRequiresFreshAuthority == s.phase = "launched" => s.launchCheck = "verified"

Safety == TypeOK /\ OwnedRetirementOnly /\ TimeoutIsMonotone
          /\ QuiescenceIsObserved /\ PreparedImageIsAdmitted /\ FirstSelectorRequiresFreshAuthority

=============================================================================
