# Testing

Run the workspace commands from [README.md](README.md) on the pinned Rust
toolchain. The [nextest profile](.config/nextest.toml) records the workspace
configuration. Use a package selection for iteration and run the workspace
and affected platform and feature lanes before integrating. Run doctests
through Cargo.

| Test scope | Location and policy |
| --- | --- |
| Unit and integration | Keep unit tests with the owning module and integration tests in the owning crate's `tests/`. Cover supported behavior, explicit refusal, interruption and retained evidence. |
| Reference and fault injection | Keep reusable test support in the [engineering testkit](crates/engineering/exacopy-testkit/). Use an independent expected result or model, exercise deliberate faults, and replay minimized failures deterministically. Run native failure tests on disposable synthetic files and record the actual filesystem profile. |
| Fuzzing | Follow the [endpoint corpus](crates/endpoints/endpoint/fuzz/README.md) and [journal corpus](crates/storage/journal/fuzz/README.md). Keep targets and corpora crate-local. Include seeded accepted cases and malformed or adversarial inputs. |
| Benchmarks | Keep benchmarks with their crate. Measure verified operations under the same integrity and durability policies. |
| Formal checks | Follow [VERIFICATION.md](VERIFICATION.md) and the owning crate's gate. |

The [feature matrix](specs/features/matrix.json) defines supported
profiles and target restrictions. See [feature checks](tools/feature_matrix.py)
for repeatable graph and build validation.

Substantial shared fixtures need provenance, a reproduction procedure,
expected properties and redistribution terms. Prefer deterministic generation
where that keeps inputs small. Freeze oracle expectations independently of
the production algorithm and include a negative control that demonstrates
the test can fail.

The [CI](.github/workflows/ci.yml) and
[nightly assurance](.github/workflows/nightly.yml) workflows define the
executed automation. Preserve raw outcomes and surface required jobs
that failed, timed out, were blocked or did not run.
