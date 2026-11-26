--------------------------- MODULE RetainedPrefix ---------------------------
EXTENDS Integers

CONSTANT Mutation
VARIABLE state

PrefixEnd == 1
SourceEnd == 3
JournalLimit == 8
InitialHistory == {"ready", "uncertain", "intent"}
PrefixFacts == {"match", "short", "badHistoryHash", "staleSource", "pastOldExtent"}
ContextChanges == {"stage", "lease", "head", "grant", "source"}

Init ==
    \E history \in InitialHistory, proof \in PrefixFacts,
       budget \in {"available", "journal", "ordinal", "receipt"}, hasTail \in BOOLEAN:
        state = [
            phase |-> "start", oldWriter |-> TRUE, history |-> history,
            proof |-> proof, context |-> "current", compared |-> FALSE,
            prefixFlushed |-> FALSE, successorDurable |-> FALSE,
            cursor |-> PrefixEnd, checkpointEnd |-> PrefixEnd, journal |-> 0,
            journalEnd |-> 0, pending |-> -1, permitSafe |-> TRUE,
            permitCheckpointed |-> TRUE, completionCurrent |-> TRUE,
            prefixIntact |-> TRUE, completion |-> "none",
            ambiguousCompletion |-> FALSE, budget |-> budget,
            permitBudgeted |-> TRUE, hasTail |-> hasTail
        ]

Drain ==
    /\ state.phase = "start"
    /\ state.oldWriter
    /\ state' = [state EXCEPT !.oldWriter = FALSE]

Compare ==
    /\ state.phase = "start"
    /\ ~state.oldWriter
    /\ state.history = "ready"
    /\ state.proof = "match"
    /\ state.context = "current"
    /\ state' = [state EXCEPT !.phase = "compared", !.compared = TRUE]

PrefixBarrier ==
    /\ state.phase = "compared"
    /\ state.context = "current"
    /\ state' = [state EXCEPT !.phase = "barrier", !.prefixFlushed = TRUE]

SyncedContinuation ==
    /\ state.phase = "barrier"
    /\ state.context = "current"
    /\ state.hasTail
    /\ state' = [state EXCEPT !.phase = "continued", !.successorDurable = TRUE,
                 !.journal = 1, !.journalEnd = 2]

LoseContext ==
    /\ state.context = "current"
    /\ \E change \in ContextChanges:
        state' = [state EXCEPT !.context = change]

BudgetAvailable ==
    /\ state.budget = "available"
    /\ state.journalEnd + 4 <= JournalLimit

ContinueWithoutTail ==
    /\ state.phase = "barrier"
    /\ state.context = "current"
    /\ ~state.hasTail
    /\ state' = [state EXCEPT !.phase = "noTail", !.successorDurable = TRUE,
                 !.journal = 1, !.journalEnd = 2]

PermitTail ==
    /\ state.pending = -1
    /\ state.hasTail
    /\ BudgetAvailable \/ Mutation = "skipBudget"
    /\ state.phase = "continued" \/ (Mutation = "earlyPermit" /\ state.phase = "barrier")
    /\ state.context = "current" \/ Mutation = "lostBinding"
    /\ state.checkpointEnd = state.cursor \/ Mutation = "skipCheckpoint"
    /\ \E offset \in 0..(SourceEnd - 1):
        /\ offset = state.cursor \/ Mutation = "prefixWrite"
        /\ state' = [state EXCEPT !.pending = offset,
             !.permitSafe = state.context = "current",
             !.permitBudgeted = BudgetAvailable,
             !.permitCheckpointed = state.checkpointEnd = state.cursor,
             !.prefixIntact = state.prefixIntact /\ offset >= PrefixEnd]

CompleteAt(cursor) ==
    /\ state.phase = "continued"
    /\ state.cursor = cursor
    /\ state.pending # -1
    /\ state.context = "current"
    /\ \E epoch \in {"old", "fresh"}, completionHead \in 1..state.journal:
        /\ epoch = "fresh" \/ Mutation = "staleCompletion"
        /\ completionHead = state.journal \/ Mutation = "staleHead"
        /\ state' = [state EXCEPT !.pending = -1, !.cursor = state.pending + 1,
             !.completion = epoch, !.completionCurrent = completionHead = state.journal]

CompleteFirst == CompleteAt(PrefixEnd)
CompleteLast == CompleteAt(PrefixEnd + 1)

MismatchCompletion ==
    /\ state.phase = "continued"
    /\ state' = [state EXCEPT !.ambiguousCompletion = TRUE,
                 !.phase = IF Mutation = "ignoreMismatch" THEN @ ELSE "blocked",
                 !.pending = IF Mutation = "ignoreMismatch" THEN @ ELSE -1]

Checkpoint ==
    /\ state.phase = "continued"
    /\ state.pending = -1
    /\ state.context = "current"
    /\ state.checkpointEnd < state.cursor
    /\ state.journalEnd + 2 <= JournalLimit
    /\ state' = [state EXCEPT !.checkpointEnd = state.cursor, !.journal = @ + 1,
                 !.journalEnd = @ + 2]

Block ==
    /\ state.phase # "blocked"
    /\ state' = [state EXCEPT !.phase = "blocked", !.pending = -1]

Next == Drain \/ Compare \/ PrefixBarrier \/ SyncedContinuation \/ ContinueWithoutTail
        \/ LoseContext \/ PermitTail \/ CompleteFirst \/ CompleteLast
        \/ MismatchCompletion \/ Checkpoint \/ Block
Spec == Init /\ [][Next]_state

PriorEvidence ==
    state.pending # -1 =>
        /\ ~state.oldWriter
        /\ state.history = "ready"
        /\ state.proof = "match"
        /\ state.compared
        /\ state.prefixFlushed
        /\ state.successorDurable

PreservedPrefix == state.prefixIntact
OnlyCurrentCompletion == state.completion # "old" /\ state.completionCurrent
CurrentPermitBinding == state.permitSafe
BoundedCursor == state.cursor \in PrefixEnd..SourceEnd
CheckpointBeforeNextPermit == state.permitCheckpointed
AmbiguousCompletionBlocks ==
    state.ambiguousCompletion => state.phase = "blocked" /\ state.pending = -1
CloseoutCapacityBeforePermit == state.permitBudgeted
BoundedHead == state.journalEnd = state.journal * 2 /\ state.journalEnd \in 0..JournalLimit
=============================================================================
