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
test evidence. The [endpoint Kani gate](../../crates/interfaces/exacopy-endpoint/verification/README.md)
defines six bounded scheduler harnesses. Execution and full P-020 extraction
remain open. The harnesses supply no actual transport, custody, or native
qualification evidence.

The experimental Linux embedded transport explicitly stops and observes its
bounded route worker after every returned post-spawn authentication, binding
or consumer outcome. Authentication refusal and cancellation are selected
before waiting for cleanup; a later interrupt cannot replace that primary
diagnosis. An unconfirmed worker retirement blocks redial and adds a fixed
diagnostic to the existing version-1 report. It does not erase known
publication or the retained job. Drop remains a last-resort fence and is
not evidence of observed worker termination. These checks implement the
application lifetime portion of R-255–257 and INV-021–023; native execution
of the added refusal and drain controls remains a separate gate.
