# Witnessed Linux components on whole ext4

The platform crate owns seven tests exercised by exact selector on the
canonical GitHub-hosted Linux x86-64 push. The runner uses the package's held
whole-ext4 mount observations and a private mode-0700 scratch parent. It runs
as an ordinary unprivileged actor. The locked offline platform build selects
one ELF by Cargo artifact identity. The supervisor executes the held image,
checks the exact one-test result, and verifies that each fixture is empty and
its process group drained. The evidence includes the selected revision, Rust
compiler, inputs and image hashes, observed mount and actor, per-selector
outcomes, and cleanup state. A missing supported substrate blocks the run.

The cases exercise protected witness hardlink creation, file and job fsync,
witness collision and refused later barrier, native exclusive publication with
success and two incumbent classes, the four postpublication file/directory
barriers and metadata-change refusal, anonymous and named KEEP_SIZE
allocation, lease behavior on submission failure, and same-descriptor journal
append/fsync with independent exact readback and EOF checks. The receipt
control also exercises closing the original anonymous writer, descriptor-linking
through the independently reopened read-only handle, and promoting the same
sealed inode to an absent final name.

These are local adapter controls for R-008, R-253, R-255 and
INV-002/003/004/006/009/013/018/019. The effect callbacks are component-test
inputs. The fixture does not create an OP2 grant, consent, eligibility record,
transport, or authentic kind-7/8/9 application transaction. In particular the
journal case exercises the native append and readback primitives with its
literal fixture bytes. It does not exercise the authenticated kind-8 or kind-9
recorder. The run provides no process-kill, power-loss, receipt, or CLI
activation evidence. It changes no protocol, model transition or proof input.

## Separately reported coverage

The optional runner mode is selected by `--coverage-only` on the canonical
GitHub-hosted main push. A caller must provision the matching Rust 1.100.0
`llvm-tools` component alongside the existing pinned build inputs. The
existing qualification job keeps its normal invocation. A separate advisory
job invokes coverage mode and retains its own evidence. The coverage runner repeats
the checkout, actor, mount, fixture and running-image checks and adds a
fixed instrumenting Rust flag after the compiler and loader override check.

The instrumented image runs the same seven exact ignored tests. Each test and
each of the fourteen listings gets its own protected profile sink outside
the test fixture. The coverage artifact retains the held ELF, seven measured
raw profiles, merged profile and LLVM summary export. The receipt binds those
inputs to the selected revision, lockfile, exact Cargo artifact and selectors.
LLVM writes the indexed profile in its own held destination directory.
Cleanup rechecks that file and all collected raw profiles through their held
descriptors. An occupied unadmitted slot or a replaced output retains the
owned work tree. Listings contribute no counters to the merge. Their receipt
entries identify the discarded profiles, which are removed with the owned work directory.
Incomplete attendance, profile admission, export and cleanup remain visible.
If custody or process drainage cannot be confirmed, the runner retains the
owned work directory and reports the cleanup failure.

This profile reports mapped platform source line and region counts separately.
It supplies neither the ordinary endpoint coverage gate nor OP2, crash or
power-loss qualification. Combining coverage with another run requires
compatible mappings and one merged export over the reviewed source inventory.
