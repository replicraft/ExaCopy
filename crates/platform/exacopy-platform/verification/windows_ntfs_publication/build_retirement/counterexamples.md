# Owned build retirement finite-state witnesses

These are hand-derived source witnesses for the [platform-owned finite model](../../tla/PublicationBuildRetirement.tla). The sequences below were derived by hand before model checking. The finite model starts after successful ownership admission. It abstracts the admitted Windows job, held root, strict transcript validator, and held image recheck into trusted observations. It checks decision ordering and evidence binding. It provides no guarantees about Windows API conformance, Cargo's grammar implementation, filesystem identities, or eventual process exit.

The first hosted check at `824521c` failed during parsing before state
exploration. At `90b5d44`, hosted TLC exhausted both corrected healthy
configurations, with 333 preparation and 21 strict distinct states and
empty queues. Preparation reached the first selector. All ten single
mutations produced the expected named invariant violation and final action.
The [contract](contract.md#scope-and-entry-point) identifies both evidence
records. The model applies these checks to trusted observations. It does
not establish implementation refinement, native Windows conformance,
process-crash behavior or power-loss qualification.

The [preparation configuration](../../tla/PublicationBuildRetirement.cfg) uses all guards. The [strict configuration](../../tla/PublicationBuildRetirement-strict.cfg) checks that the legacy path can never issue a planned preparation retirement. Its existing natural completion is outside the modeled preparation transitions.

The shortest happy path uses the following actions from the initial state:

1. `ObserveRoot("zero", "own")`.
2. `RequestRetirement("own")`.
3. `ObserveStop("success", "own")`.
4. `ObserveDrain(TRUE, TRUE, TRUE, TRUE)`, reporting active zero, stdout EOF, stderr EOF, and confirmed sink extents.
5. `ClassifyQuiesced`. At this point the process evidence is complete and there is no image authority.
6. `CheckTranscript("verified")`.
7. `CheckHeldImage("verified")`.
8. `IssuePreparedImage`.
9. `IssueFirstSelector("verified")`, after fresh source, lockfile and held-image verification.

The path through step 5 is also valid for a failed transcript. `CheckTranscript("refused")` followed by `Fail` records zero selectors even though the process quiesced. Similarly, `CheckHeldImage("uncertain")` after step 6 yields zero selectors. Windows queue notifications do not participate in these decisions.

The following traces should violate the named invariant only when the corresponding single mutation is enabled. References to steps use the happy path above.

| Mutation | Witness transition sequence | Violated invariant |
| --- | --- | --- |
| `strict-stop` | Set `Mode = "strict"`. Steps 1–2 attempt planned retirement from the existing generic route. | `OwnedRetirementOnly` |
| `foreign-job` | Step 1, then `RequestRetirement("foreign")` tries to use a different job object. | `OwnedRetirementOnly` |
| `ignore-root` | `ObserveRoot("unknown", "own")`, then step 2. A stale zero from `"foreign"` gives the same refusal. | `OwnedRetirementOnly` |
| `late-request` | Step 1, `Expire`, then step 2. | `OwnedRetirementOnly` |
| `ignore-stop` | Steps 1–2, then `ObserveStop("unknown", "own")` and steps 4–5. Later cleanup reports a drained process tree but cannot prove the original stop acknowledgment. | `QuiescenceIsObserved` |
| `ignore-stdout` | Steps 1–3, then `ObserveDrain(TRUE, FALSE, TRUE, TRUE)` and step 5. | `QuiescenceIsObserved` |
| `clear-timeout` | Steps 1–4, `Expire`, then step 5. | `TimeoutIsMonotone`, `QuiescenceIsObserved` |
| `trust-root-output` | Steps 1–5, `CheckTranscript("refused")`, then steps 7–8. | `PreparedImageIsAdmitted` |
| `skip-image` | Steps 1–6, `CheckHeldImage("uncertain")`, then step 8. | `PreparedImageIsAdmitted` |
| `stale-launch` | Steps 1–8, then `IssueFirstSelector("refused")` when rechecking the source or held image fails. | `FirstSelectorRequiresFreshAuthority` |

The source model has separate output-quiescence and transcript-verification states by design. The native supervisor receives no JSON parser or callback. It may return a quiescence receipt for invalid compiler stdout, and the parent must then refuse artifact admission. A completed selector run requires the valid transcript and held image; a process exit or a stop return in isolation provides neither.

Concrete replay cases beyond the abstract model are missing/false/duplicate `build-finished`, bytes after the terminal marker, partial JSONL, invalid UTF-8, duplicate JSON object keys, a duplicate selected artifact, the wrong package/feature/profile/target, hidden reparse or path rebinding, short or altered sink read-back, mismatched invocation, and changed checkout/lockfile before first selector. Replay cases should use bounded payloads and preserve candidate negative outcomes. The bundled prebuild controls exercised synthetic preparation inputs and existing process controls. Native v2 replay remains pending.
