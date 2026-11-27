# Read-only public-stage inspection

`inspect_public_stage_with_job` inspects the experimental public staging
profile. It authenticates the selected profile's signed owner, binds the
private Plan and native roots, replays only stage preparation and verification
records, and checks current namespace observations. It never creates, resumes,
retries, truncates, renames or removes anything.

The capability exposes checked optional opens for the fixed owner, Plan and
first segment. Observed absence is distinct from an open error. Missing owner
leaves the job flavor unknown; authenticated owner with a missing Plan or
segment reports that absence without inferring why it occurred. Malformed or
changing required artifacts are errors. No namespace inventory occurs before
authentication and Plan binding succeed.

The parser requires the exact public/private association, expected stream and
metadata policy. Complete publication intent or recovery-start records are
unsupported in this stage-only profile. A torn suffix requires reconciliation.
A retained verified stage needs a complete clean bound seal, verification and
metadata history, matching native identity, and fresh matching stage bytes and
metadata. A present target without supported intent, an unexpected receipt,
missing stage or unknown identity yields an explicit weaker observation.

Results carry historical evidence and point-in-time observations, never a
publication permit. Expiry is inspectable historical data. Legacy mutating
recovery continues to refuse the public owner form; a future public-aware
publication/recovery path needs its own fresh gate and supported intent rules.
The library inspector is not yet exposed as a CLI command.

Ninety portable transfer tests passed in the separately labeled macOS
capability harness, including five public inspection cases. Three deliberate
guard regressions were caught. The actual Linux-target implementation and
native optional-open fixture sources passed strict cross Clippy. Native
Linux adapter execution was outside that earlier portable run. Its review
record was written to
`/private/tmp/exacopy-public-stage-inspection.ZVH0JCLh/review.md`.

## Native stage and inspection evidence

At `09b96f5` the hosted whole-ext4 profile passed its one exact selector,
`approved_stage_reopens_with_exact_owner_and_preserves_uncertain_evidence`,
as unprivileged UID/GID 1001 on Linux `7.0.0-1020-azure`. The held test
admitted a public Plan, staged the approved stream privately, then
reopened the destination under a read lease after the staging invocation
released its handles. The inspector matched the authenticated owner and
public/private binding, independently confirmed the retained verified
stage and its exact bytes, and observed the target absent.

The same fixture refused a wrong approved digest before creating a job
and a wrong owner key on reopen. The legacy inspector refused the public
owner form. An equal-length source change on the original inode left a
retained partial stage and failed the approved stream check. A synthetic
torn suffix kept the accepted journal boundary and required reconciliation.
A late incumbent blocked new staging before job creation and was reported
as an unexpected target by the inspector. It kept its inode and bytes.

The three listing and execution process groups drained and owned work
removal was verified. All 21 input digests matched the exact Git revision.
The held ELF SHA-256 was `c729ec470678b2f41450fcc6edc2205e25cc6367e34a47dbb0699daa75ff587f`.
The result JSON SHA-256 was
`f934d2ae7b04695efbc3c1d3234d5dfd76d08fffafb7524cc218bfa880577243`. Raw evidence is retained
under `target/agent-evidence/hosted-09b96f5/`.
[Hosted run](https://github.com/replicraft/ExaCopy/actions/runs/45932645117) ·
[Native stage report](https://github.com/replicraft/ExaCopy/actions/runs/45932645117/artifacts/15169004426)

This run covers private staging and read-only inspection. The fixture
injects a torn suffix directly. Process interruption, publication intent,
public apply and commit, and power-loss qualification remain open.
