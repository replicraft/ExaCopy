-------------------------- MODULE ProtectedReplacement --------------------------
EXTENDS Naturals, FiniteSets

CONSTANT Mutation
VARIABLE state

Empty == "absent"
Source == "read-only source"
Approved == "approved incumbent"
Stage == "verified replacement"
Foreign == "racing file"
Opaque == "racing opaque entry"
Arrival == "arrives during gap"
Private == "private incumbent"
Wrong == "unmatched post-barrier report"
Fresh == "fresh pre-intent history"
Prior == "prior intent"
Indeterminate == "ambiguous replay"

Terminal == {"reconcile", "stale", "conflict", "seen-placement", "cancelled"}

Init ==
	\E imageRequired \in BOOLEAN, history \in {Fresh, Prior, Indeterminate}:
		state = [
			phase |-> "prepared",
			history |-> history,
			source |-> Source,
			target |-> Approved,
			private |-> Empty,
			stage |-> Stage,
			outside |-> {},
			external |-> {},
			origin |-> Empty,
			report |-> Empty,
			captureCount |-> 0,
			publishCount |-> 0,
			captureIntent |-> FALSE,
			publishIntent |-> FALSE,
			publicBarrier |-> FALSE,
			privateBarrier |-> FALSE,
			captureRecord |-> FALSE,
			imageRequired |-> imageRequired,
			imageReady |-> FALSE,
			displacedAtPublish |-> Empty,
			uncertain |-> FALSE
		]

RecordCaptureIntent ==
	/\ state.phase = "prepared"
	/\ state.history = Fresh \/ Mutation = "admit-prior-history"
	/\ state.target = Approved
	/\ state' = [state EXCEPT !.phase = "intent", !.captureIntent = TRUE]

RejectHistoricalAdmission ==
	/\ state.phase = "prepared"
	/\ state.history # Fresh
	/\ state' = [state EXCEPT !.phase = "reconcile"]

GrantCapture ==
	/\ state.phase = "intent"
	/\ state' = [state EXCEPT !.phase = "capture", !.captureCount = @ + 1]

RebindBeforeCapture ==
	/\ state.phase \in {"intent", "capture"}
	/\ state.target = Approved
	/\ \E opponent \in {Foreign, Opaque}:
		state' = [state EXCEPT !.target = opponent, !.outside = @ \cup {Approved},
			!.external = @ \cup {opponent}]

OccupyPrivateSlot ==
	/\ state.phase = "capture"
	/\ state.private = Empty
	/\ state' = [state EXCEPT !.private = Private, !.external = @ \cup {Private}]

CaptureActual ==
	/\ state.phase = "capture"
	/\ state.private = Empty
	/\ state.target # Empty
	/\ \E received \in BOOLEAN:
		state' = [state EXCEPT
			!.private = IF Mutation = "capture-prior" THEN Approved ELSE state.target,
			!.origin = state.target, !.target = Empty,
			!.phase = IF received THEN "captured" ELSE "reconcile",
			!.uncertain = ~received]

CaptureBlocked ==
	/\ state.phase = "capture"
	/\ state.private # Empty
	/\ state' = [state EXCEPT !.phase = "conflict"]

LatePublicArrival ==
	/\ state.phase \in {"captured", "retained", "publication-intent", "publication"}
	/\ state.target = Empty
	/\ state' = [state EXCEPT !.target = Arrival, !.external = @ \cup {Arrival}]

SyncPublic ==
	/\ state.phase = "captured"
	/\ ~state.publicBarrier
	/\ state' = [state EXCEPT !.publicBarrier = TRUE]

SyncPrivate ==
	/\ state.phase = "captured"
	/\ ~state.privateBarrier
	/\ state' = [state EXCEPT !.privateBarrier = TRUE]

PostBarrierObservation ==
	/\ state.phase = "captured"
	/\ state.publicBarrier \/ Mutation = "skip-public-barrier"
	/\ state.privateBarrier \/ Mutation = "skip-private-barrier"
	/\ state.report = Empty
	/\ \E observed \in {state.private, Wrong}:
		state' = [state EXCEPT !.report = observed]

CommitCaptureEvidence ==
	/\ state.phase = "captured"
	/\ state.report = state.origin \/ Mutation = "trust-post"
	/\ state.report # Empty
	/\ state' = [state EXCEPT !.captureRecord = TRUE,
		!.phase = IF state.origin = Approved \/ Mutation = "allow-foreign"
			THEN "retained" ELSE "stale"]

RefuseWrongObservation ==
	/\ state.phase = "captured"
	/\ state.report = Wrong
	/\ state' = [state EXCEPT !.phase = "reconcile", !.uncertain = TRUE]

VerifyIndependentImage ==
	/\ state.phase = "retained"
	/\ state.imageRequired
	/\ ~state.imageReady
	/\ state' = [state EXCEPT !.imageReady = TRUE]

RefuseImage ==
	/\ state.phase = "retained"
	/\ state.imageRequired
	/\ ~state.imageReady
	/\ state' = [state EXCEPT !.phase = "reconcile", !.uncertain = TRUE]

RecordPublicationIntent ==
	/\ state.phase = "retained"
	/\ ~state.imageRequired \/ state.imageReady \/ Mutation = "skip-image"
	/\ state' = [state EXCEPT !.phase = "publication-intent", !.publishIntent = TRUE]

GrantPublication ==
	/\ state.phase = "publication-intent"
	/\ state' = [state EXCEPT !.phase = "publication", !.publishCount = @ + 1]

PlaceStage ==
	/\ state.phase = "publication"
	/\ state.target = Empty \/ Mutation = "clobber-arrival"
	/\ \E received \in BOOLEAN:
		state' = [state EXCEPT !.target = state.stage, !.stage = Empty,
			!.displacedAtPublish = state.target,
			!.phase = IF received THEN "seen-placement" ELSE "reconcile",
			!.uncertain = ~received]

PublicationConflict ==
	/\ state.phase = "publication"
	/\ state.target # Empty
	/\ state' = [state EXCEPT !.phase = "conflict"]

LoseReplyBeforeEffect ==
	/\ state.phase \in {"capture", "publication"}
	/\ state' = [state EXCEPT !.phase = "reconcile", !.uncertain = TRUE]

Interrupt ==
	/\ state.phase \notin Terminal
	/\ state.phase # "prepared" \/ state.history = Fresh
	/\ state' =
		IF state.phase = "prepared"
		THEN [state EXCEPT !.phase = "cancelled"]
		ELSE [state EXCEPT !.phase = "reconcile", !.uncertain = TRUE]

RetryUnknown ==
	/\ Mutation = "retry-unknown"
	/\ state.phase = "reconcile"
	/\ state.captureCount = 1
	/\ state' = [state EXCEPT !.phase = "capture", !.captureCount = @ + 1]

Next ==
	\/ RecordCaptureIntent
	\/ RejectHistoricalAdmission
	\/ GrantCapture
	\/ RebindBeforeCapture
	\/ OccupyPrivateSlot
	\/ CaptureActual
	\/ CaptureBlocked
	\/ LatePublicArrival
	\/ SyncPublic
	\/ SyncPrivate
	\/ PostBarrierObservation
	\/ CommitCaptureEvidence
	\/ RefuseWrongObservation
	\/ VerifyIndependentImage
	\/ RefuseImage
	\/ RecordPublicationIntent
	\/ GrantPublication
	\/ PlaceStage
	\/ PublicationConflict
	\/ LoseReplyBeforeEffect
	\/ Interrupt
	\/ RetryUnknown

Spec == Init /\ [][Next]_state

ActualEntryRetained ==
	state.origin # Empty => state.private = state.origin

NoPublicClobber ==
	state.displacedAtPublish = Empty

EveryProtectedEntrySurvives ==
	/\ state.source = Source
	/\ {Approved, Stage} \cup state.external
		\subseteq {state.target, state.private, state.stage} \cup state.outside

PublicationRequiresDurableApprovedCapture ==
	state.publishCount > 0 =>
		/\ state.captureIntent
		/\ state.publishIntent
		/\ state.captureRecord
		/\ state.publicBarrier
		/\ state.privateBarrier
		/\ state.origin = Approved
		/\ state.report = Approved
		/\ state.private = Approved
		/\ ~state.imageRequired \/ state.imageReady

FreshAdmission ==
	state.history # Fresh =>
		/\ ~state.captureIntent
		/\ state.captureCount = 0
		/\ state.publishCount = 0

OneShot ==
	/\ state.captureCount <= 1
	/\ state.publishCount <= 1
	/\ state.captureCount > 0 => state.captureIntent

UncertaintyStops ==
	state.uncertain => state.phase = "reconcile"

=============================================================================
