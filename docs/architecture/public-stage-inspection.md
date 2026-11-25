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
Linux adapter execution remains unrun for this new path. Exact evidence is
retained in `/private/tmp/exacopy-public-stage-inspection.ZVH0JCLh/review.md`.
