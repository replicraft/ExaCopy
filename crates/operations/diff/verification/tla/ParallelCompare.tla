--------------------------- MODULE ParallelCompare ---------------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANT Workers, AllowEarlyReturn
VARIABLES oracle, next, outcomes, joined, failed, returned, answer

Indices == 1..Workers
Observed == {"equal", "mismatch", "read_error"}
Unset == "unset"
Finished == Observed \cup {"skipped", "panic"}
Vars == <<oracle, next, outcomes, joined, failed, returned, answer>>

First(indices) == CHOOSE i \in indices : \A j \in indices : i <= j

Decision(results) ==
	LET decisive == { i \in Indices : results[i] \in {"mismatch", "read_error"} }
	IN IF decisive = {} THEN <<"equal", 0>>
	   ELSE <<results[First(decisive)], First(decisive)>>

Init ==
	/\ oracle \in [Indices -> Observed]
	/\ next = 1
	/\ outcomes = [i \in Indices |-> Unset]
	/\ joined = 0
	/\ failed = FALSE
	/\ returned = FALSE
	/\ answer = <<Unset, 0>>

Start ==
	/\ next \in Indices
	/\ ~failed
	/\ next' = next + 1
	/\ UNCHANGED <<oracle, outcomes, joined, failed, returned, answer>>

FailStart ==
	/\ next \in Indices
	/\ ~failed
	/\ failed' = TRUE
	/\ UNCHANGED <<oracle, next, outcomes, joined, returned, answer>>

Finish(i) ==
	/\ i < next
	/\ outcomes[i] = Unset
	/\ LET maySkip == failed
		\/ \E j \in Indices : j < i /\ outcomes[j] \in {"mismatch", "read_error"}
	   IN \E result \in IF maySkip THEN {oracle[i], "panic", "skipped"}
		ELSE {oracle[i], "panic"} :
		outcomes' = [outcomes EXCEPT ![i] = result]
	/\ UNCHANGED <<oracle, next, joined, failed, returned, answer>>

Join ==
	/\ failed \/ next = Workers + 1
	/\ joined + 1 < next
	/\ outcomes[joined + 1] \in Finished
	/\ joined' = joined + 1
	/\ failed' = (failed \/ outcomes[joined + 1] = "panic")
	/\ UNCHANGED <<oracle, next, outcomes, returned, answer>>

Return ==
	/\ failed \/ next = Workers + 1
	/\ joined = next - 1 \/ AllowEarlyReturn
	/\ returned' = TRUE
	/\ answer' = IF failed THEN <<"worker_error", 0>> ELSE Decision(outcomes)
	/\ UNCHANGED <<oracle, next, outcomes, joined, failed>>

Next ==
	IF returned THEN UNCHANGED Vars
	ELSE Start \/ FailStart \/ (\E i \in Indices : Finish(i)) \/ Join \/ Return

Spec == Init /\ [][Next]_Vars

AllJoinedAtReturn == returned => joined = next - 1

SerialDecisionAtSuccess ==
	returned /\ answer[1] # "worker_error" => answer = Decision(oracle)

=============================================================================
