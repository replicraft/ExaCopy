# Checked local public apply

The Linux SDK `apply_qualified_public_plan`, behind the default-off
`experimental-linux-public-apply` feature, carries one fresh
create-new action from its original held source and private stage through
exclusive publication and a physically confirmed receipt commitment. The
ordinary copy path and historical intent proposer retain their interfaces.
No CLI selector, retry, prefix resume or public-v2 recovery writer is enabled.

The trusted embedding host supplies an independent foreground Plan digest,
entry, root and profile selection. It consumes one `LocalApplyIssuer` to
issue a noncloneable invocation grant. Decoded Plan or journal bytes, the
owner signing key and the qualification attestor cannot issue this approval.
The existing [local qualification](local-public-apply-qualification.md) must
also match the running executable, held roots, native environment and exact
action. No operational enrollment ships with the SDK.

One mutex serializes revocation, the shared UTC high-water mark, finite
monotonic deadline and phase transitions. The original Plan and signed
qualification retain their exclusive UTC expiries. Each bounded private mutation
reacquires admission. Stage writes stay inside the approved extent and buffer
ceiling. A journal append guard spans the started frame and its file barrier.
Outside rename settlement, other file and directory barriers receive separate admission.
Individual I/O calls and existing write helpers may block or retry interrupted
calls, so this supplies no hard wall-time or syscall-count guarantee.

The runtime clock delegates its scalar decision to
`exacopy_model::grant_time::check_grant_time`. Either clock's regression wins
over expiry. UTC windows retain nanosecond precision and signed seconds;
qualification can only narrow the original interval. The app still samples
both clocks, classifies the native monotonic sample, retains the original
deadline and updates the paired high-water only after acceptance. Installing
a valid qualification still precedes observation, including a refused sample.
P-083 defines Rust and Kani checks for the scalar decision; its proof is
unexecuted and does not verify those native or stateful premises. Extraction
and a theorem over the generated function remain open.

The engine retains the original source, exclusive job, owner and private Plan
read-only pins, verified stage, model session and journal. It checks the source
name, required metadata, selected target absence, current qualification and
original record identities. It appends the existing v2 kind-7 intent under
admission, decodes its actual payload and confirms the original physical chain
and EOF before asking the original model session for its one-use permit.

After native readiness and final evidence checks, one-shot rename admission is spent under
the same revocation lock immediately before one kernel no-replace rename.
There is no intervening namespace lookup under that guard. It is released
after submission. An acknowledged or ambiguous submission receives bounded
observations and independent attempts on both original directory barriers,
even if approval later expires or the first observation or barrier fails.
These two barriers settle the admitted operation. They authorize no later
write. Ambiguous submission remains reconciliation even when observations
subsequently match. The path checks source and incumbent protection under the
held cooperative custody premises. It does not make source-name checking and
the destination rename one atomic operation.

Verified settlement checks the original inode and required metadata,
including preserved atime and a stable post-rename ctime. Every kind-8, kind-9,
receipt and kind-18 mutation requires fresh admission from the same grant.
Expiry or revocation can therefore leave a known publication with incomplete
evidence. The SDK makes no further rename or rollback and reports acknowledged
publication with incomplete evidence. Its return types distinguish this from an unknown result
and from refusal before any public rename was submitted.

Successful closeout retains the same-inode receipt through exact readback,
decoding and terminal journal confirmation. The journal scanner reads the
complete original chain under the existing 64 MiB segment limit without
read-ahead, captures literal bytes after the
actual kind-4 seal through the actual kind-18 frame, and probes physical EOF
separately. The suffix has a 4096-byte limit. All prefix, suffix and probe reads
share sixteen interrupted-call retries, and each call must return. The generic
frame parser retains its one-MiB malformed-payload allocation bound. Caller
output changes only after cursor restoration and final native extent checks.
The existing v2 receipt validator checks those literal bytes and the observed
artifact. Final receipt, published file, job records and journal rechecks
precede the original model's receipt event and the returned historical head.

Source controls cover grant poisoning, expiry, rollback, scope and reuse;
original-record rebinding; refused native mutations; metadata preservation;
both barriers after observation failure or an ambiguous reply; and literal
suffix, EOF and cursor failures. The existing owned ext4 fixture also calls
the real SDK with absent enrollment, spent approval and revoked approval.
Synthetic component authority is distinct from operational qualification.

At `3b9ef5f`, hosted native tests and strict lint passed on Linux, macOS and
Windows. Linux executed eight grant, nine journal and six native component
controls. The owned ext4 fixture executed the unenrolled, spent and revoked
SDK refusals with verified cleanup. [Exact native run](https://github.com/replicraft/ExaCopy/actions/runs/46118308336)
and [owned ext4 run](https://github.com/replicraft/ExaCopy/actions/runs/46118308431)
retain that bounded evidence. Proofs of new policy and positive end-to-end
native qualification remain open. Activation requires
independently reviewed exact-build evidence and runtime verification of the
separately selected [read-only reconciliation caller](public-apply-reconciliation.md).
That caller now has a source implementation. The stage-only inspector still refuses intent
suffixes. No process-crash or power-loss success claim follows from this source.
