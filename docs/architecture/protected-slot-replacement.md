# ADR proposal: Bounded public-slot relocation for protected replacement

## Context

ADR-022 preserves the actual incumbent and allows a disclosed visibility gap.
Its race acceptance A-031 expects retention of the object that actually
occupied the public name at capture. Plan history expects one specific
incumbent identity. A prelookup cannot make a pathname operation conditional
on that identity. The current Plan leaf and ordinary copy authority support
only create-new. The journal recognizes incumbent intent and observation
discriminants, but does not currently implement their payloads.

## Decision

Select a separate opt-in protected-slot profile. The grant explicitly admits
one opaque no-replace relocation from one independently authorized, literal
public parent and raw component to one independently authorized, reserved
private parent and raw component. It covers the entry that actually occupies
the public slot at the effect, even if that entry differs from the expected
incumbent or changed kind. It does not provide a general capture, read,
recursive operation, overwrite, delete or purge interface. An ordinary worker
has no slot-relocation or restoration authority.

The approval binds the exact reviewed single-entry plan, owner and current
grant selection, qualified implementation and layout, exact public and
recovery slots, expected incumbent identity and policy, replacement stage
and source identity, one attempt and current epoch, effect-count and
required image budget, expiry and revocation. A signed plan or a recorded
grant identifier by itself is not live authority. The coordinator rechecks
current authorization and retains its serialization through the actual
effect. The ordinary exclusive publication grant remains separate. A slot
relocation grant only covers capture; it cannot authorize publishing a
different stage or restoring the captured object.

Before capture, the approved incumbent must have been independently
observed as the exact expected ordinary file. The prelookup is stale-plan
screening; it is not the authority for a later path-bound relocation. A
racing symlink or other unsupported entry may be relocated as an opaque
entry. Do not follow its referent, inspect its payload, traverse a subtree,
copy its data, change its attributes or recursively remove anything. A
racing directory may temporarily become unavailable at its original path,
including its descendants. This availability consequence and the possibility
of a private retained foreign entry require explicit approval. No continuously
visible atomic replacement is promised.

## Qualification assumptions

The full effect operates on held, separately identified source, public and
private recovery roots. The sealed stage is held in its own protected parent.
The capture and publication slots are on the same positively admitted volume
as the sealed replacement and use no-replace. The layout excludes all
selected roots, the stage, journal and protected version storage from the
subtree that the public slot could own at the effect. Distinct root identity
alone does not prove this exclusion. The native owner proves confinement and
separation against aliases, rebinding and nested mounts for the entire
operation. A source on a distinct, separately admitted filesystem can help
prevent inode aliases, but its mount placement must still enforce the
subtree exclusion. A same-volume source needs an equally qualified
structural exclusion of protected-object aliases; a previous path lookup or
link-count observation does not give that guarantee. When unsupported, the
profile refuses before capture.

The selected namespace operation moves the slot occupant at the effect,
without following a symlink or crossing a mount, and atomically refuses a
private incumbent. A handle-based operation that relocates an earlier
object after the slot changes does not meet this contract. Qualification
must account for the filesystem's native name equivalence, including case
and alternate short-name aliases where applicable. An unresolved alias
or an unqualified slot-at-effect primitive prevents admission. The
qualified private namespace lease excludes manipulation of the retained
entry by other actors in the admitted trust model. The qualification
separately names the file and directory barriers and their crash model. An
unsupported flag, ambiguous identity, failed barrier or unavailable
authorization cannot justify an inferred effect, success or downgrade.

## Ordering and outcomes

1. Bind one source, one exact approved incumbent and one separate sealed
   replacement stage. Complete writer quiescence, data and required metadata
   barriers, independent verification and a current seal. Revalidate live
   authorizations and the qualified namespace. Persist and independently
   acknowledge a bounded capture intent bound to the plan, slots and exact
   attempt. Authorize at most one opaque exclusive relocation.
2. Observe the outcome. An unknown reply stops mutation and requires
   reconciliation. On a known capture, observe the exact private retained
   slot without following a referent, including the actual entry identity
   and kind if these are available. The durable capture evidence requires
   both ordered namespace barriers and an independent then-current no-follow
   observation of the same retained identity at the exact private slot.
   Check that identity against the protected source and sealed stage, as
   well as the approved incumbent. Protective barriers and recording rely
   on their own non-namespace-changing capabilities. Any unknown, mismatch,
   alias or unsupported kind is terminal for active publication and
   recapture. Preserve the captured entry and the stage. Incomplete evidence
   cannot support a claim that retention is already durable.
3. Only the exact approved captured incumbent can enable normal continuation.
   A point-in-time image policy requires separately admitted current
   exact-object read and private image-creation capability. The read
   selection binds the retained identity and held recovery slot; the
   relocation grant by itself does not cover it. Require a stable captured
   view and an independently verified, durably retained, separately
   identified image. A hard link or the original captured inode is
   insufficient. A failed image never justifies deleting the original
   or publishing.
4. A new, independently acknowledged publication intent and live create-new
   authority may issue one no-clobber placement of the original verified
   replacement stage. Arrival in the public gap is conflict. Preserve the
   arrival, captured object and stage. After a possibly effective publication
   do not retry blindly or unlink the target to simulate rollback.
5. Restoration has a distinct current grant over the actually observed
   captured identity and original slot, its own durable restoration intent,
   fresh namespace/identity checks and no-clobber operation. If the original
   slot is taken or identity is unclear, preserve the private captured entry.
   Recovery can inspect and report states; history cannot reconstruct live
   capture, publication, restoration or deletion authority. The first pure
   model only identifies states requiring separate restoration admission.

## Verification and compatibility

Keep changes in the pure exacopy-model ownership boundary. Maintain the
current preserve-mode decision API and CreateNew wire bytes. No protected
Plan codec, journal payload, native operation, CLI action, restoration
decision, release profile or native qualification is implied.

Trace R-031 through R-034 and A-031 through A-034 with INV-002 through
INV-007, INV-009, INV-018, INV-019 and INV-020 as applicable. Use exact Rust
transition tests plus an independent finite namespace model. Explore a
foreign arrival before capture, unsupported kinds as opaque captures,
wrong post-barrier identity, reserved private slot conflict, lost replies,
both missing barriers, missing image evidence and a racing public arrival
after capture. Require negative controls for wrong-object publication,
early publication and a clobbered late arrival. Process and power-loss
qualification remain separate from these pure checks.
