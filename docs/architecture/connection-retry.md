# Connection retry policy

The endpoint crate's `connection_retry` module supplies pure scheduling for
R-231, R-255–257 and R-261, with INV-021 and INV-023. The application supplies
one monotonic clock epoch, jitter, authorization expiry and truthful adapter
observations. It reserves a unique supervisor owner and labels each attempt.
No networking, credential storage or durable job execution occurs here.

Only safe transient failures retry automatically. Equal-jitter delays begin at
500–1,000 ms and grow to a 30–60 second cap without a retry-count limit.
Successful activity and 30 seconds of observed health are both required to
reset the penalty. Clock rollback, exhausted generations, grant expiry or
revocation stop scheduling. Definitive authentication, host, configuration,
capability and integrity refusals stop. Uncertain effects require reconciliation.

Admission requires route, SSH and source observations labeled with the same
current attempt. The opaque connection binding includes the admitted source
epoch. Old completions cannot admit current work. These labels do not prove
route confinement, trust or byte equality: the owning adapters and coordinator
must establish those facts and match each request, job, entry and stage.

Tests include a five-day simulated outage, stale and cross-owner evidence,
expiry, waiting-state revocation and ambiguity preservation. Ten compiling
guard-removal controls failed their targeted assertions. This is scheduler
test evidence; P-020's extracted proof, real transport recovery, persistent
jobs, credential reacquisition and verified range resume remain open.
