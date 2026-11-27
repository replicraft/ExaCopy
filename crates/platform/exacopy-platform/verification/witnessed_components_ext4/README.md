# Witnessed Linux components on whole ext4

The platform crate owns six existing tests exercised by exact selector on the
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
append/fsync with independent exact readback and EOF checks.

These are local adapter controls for R-008, R-253, R-255 and
INV-002/003/004/006/009/013/018/019. The effect callbacks are component-test
inputs. The fixture does not create an OP2 grant, consent, eligibility record,
transport, or authentic kind-7/8/9 application transaction. In particular the
journal case exercises the native append and readback primitives with its
literal fixture bytes. It does not exercise the authenticated kind-8 or kind-9
recorder. The run provides no process-kill, power-loss, receipt, or CLI
activation evidence. It changes no protocol, model transition or proof input.
