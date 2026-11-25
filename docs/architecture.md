# Architecture

ExaCopy admits a file operation through typed capabilities. Its preserve-mode
decision model authorizes exclusive publication only after identities match,
writers are quiescent, read-back and required metadata checks pass, and
publication intent is durable. An uncertain result enters reconciliation.
The [foundation work package](foundation.md) defines the model and its
assurance boundary. The [local adapter](local-adapter.md) and
[verified staging](verified-staging.md) record implemented platform
behavior, recovery paths and their evidence.

| Owner | Boundary |
| --- | --- |
| Applications | Parse user intent, select the concrete platform implementation and compose capabilities with engines. Render engine results and map them to exit status or UI state. |
| Local runtime | Compose held native capabilities with reusable operation policies. Linux CLI planning, copy and recovery use `exacopy-engine`. The experimental managed APFS library also composes the native adapter with transfer policy there. |
| Core model | Own typed identities, checked ranges and pure preserve-mode transitions. Keep OS, database, async runtime, network implementation and presentation dependencies outside this boundary. |
| Endpoint contracts | Define bounded capabilities that callers can supply and adapters can implement. Represent unsupported operations explicitly. |
| Operation engines | Own comparison, transfer orchestration, recovery decisions and eventual synchronization/conflict policy. Consume capabilities. |
| Native platform code | Own operating-system handles, identity observation, leases, barriers, exclusive namespace operations and narrow FFI. Expose platform facts through the endpoint contracts. |
| Storage | Own integrity primitives, bounded record codecs and journal framing. |
| Engineering | Provide policy and evidence tooling, fixtures and independent test oracles. Production paths have no engineering dependencies. |

The [dependency matrix](specs/architecture/dependencies.toml) is the
enforced package-level authority for operation contracts and native composition.
Run the [engineering policy check](testing.md). Source review also follows
the actual call graph because a permitted package edge does not establish
how authority moves through a function.

Linux planning and fresh execution consume endpoint observations, staging,
checkpoint, and publication capabilities. Transfer staging consumes endpoint
read, write, close and metadata capabilities.
Linux job bootstrap and publication, and the experimental APFS publication
coordinator, sequence their effects through supplied capabilities. Native
facades preserve the existing entry points and translate adapter failures.
Recovery classification consumes independently obtained observations. Linux
and experimental APFS recovery run through held job, inventory, and stage
capabilities. Native entry points and their adapter errors live in the runtime.
Transfer policy uses endpoint contracts, core types, and storage records.

Generic I/O or network libraries belong outside product workflows.
When transports are introduced, one capability policy owns admission and
credential acquisition. Transports receive scoped authorization and
translate their native observations into the shared contracts.

[Contract versioning](architecture/contract-versioning.md) defines
independent public and persistent boundaries. [Technical stack](tech-stack.md)
tracks adopted dependencies. [Roadmap](roadmap.md) gives the order for
extending the system. [Requirements traceability](architecture/requirements.md)
connects the admitted profiles to tests, proof obligations and open gates.
