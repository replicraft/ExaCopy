# ExaCopy command-line interface

The `exacopy` binary compares regular local files and copies one regular file to a new name on Linux. The default output is human-readable. Exact byte comparison is the default and can be requested explicitly.

```sh
cargo run --locked -p exacopy-cli -- diff ./left ./right
cargo run --locked -p exacopy-cli -- diff /path/to/left /path/to/right --compare bytes --workers 4 --format json
```

The default comparison runs serially. Use `--workers N` after the two paths to set a ceiling from 1 through 16 for positioned reads. The comparator uses up to that many workers within the same 8 MiB scratch budget. All worker choices use the same byte relation, report format, and exit codes.

Each input may be absolute or relative to the current working directory. The command opens the named parent directory and selects its final filename within that capability. Linux file names are preserved as raw bytes. A trailing separator, a reserved final component, a final symlink, or a non-regular file is refused. A parent path is the directory the caller chose, following ordinary Linux directory resolution. A filename that matches a help flag can be passed after `diff --` or with a leading `./`.

| Exit | Outcome |
| --- | --- |
| 0 | Equal over all bytes of the two recorded extents |
| 1 | A difference in recorded length or byte content |
| 2 | Inconclusive, unsupported platform, invalid usage, or failed output |

The `exacopy.cli.diff` JSON summary has `schema_version` set to `1.0`, `relation` set to `bytes`, a `result` of `equal`, `different`, or `inconclusive`, and a `complete` Boolean for the relation decision. Successful decisions carry `consistency` set to `live_observed`. The lengths and offset are unsigned decimal strings. A first-byte offset is zero-based and establishes inequality. The summary reports a single witness. Inconclusive comparisons include an `error` with a stable code and an explanation. Invocation errors are written to stderr. The paged diff report, shell completions, and generated argument parser are outside this initial command.

The command exercises the byte comparison and exit-status portions of the local CLI design. It has no persistent job, mutation, or publication authority. See the [diff crate](../../operations/diff/README.md) for evidence scope and source-observation limits.

## Copy one regular file

```sh
cargo run --locked -p exacopy-cli -- profile init ./private-profile
cargo run --locked -p exacopy-cli -- copy ./source ./new-name --profile ./private-profile --format json
```

Create the profile once under a parent owned by your account or root. A parent writable by other accounts also needs the sticky bit. The CLI creates an owner-only directory (0700) with an owner-only Ed25519 seed file (0600). Keep the profile separate from data being transferred and select the same profile explicitly for later operations on the job. The path to the profile identifies the local authorization. The seed stays in the profile. The final profile and seed components must be regular directory and file entries respectively, with no symlinks and a single link to the seed. Restrictive creation masks or interrupted initialization can leave an incomplete profile for the caller to inspect.

The destination must be a previously absent name beneath a managed directory. An existing directory, dangling symlink, hard link, or file at that name is a conflict. The adapter refuses source symlinks and unsupported metadata. Source and target are selected as raw final filename components, with the same parent handling as `diff`. Use `copy --` when the source starts with a dash.

The CLI retains each started job in the destination parent under `.exacopy-<job-uuid>` with a signed owner record, a plan, a journal, and a committed receipt on success. A late failure may report the job name so its evidence can be inspected. The CLI leaves any private job material in place. The source is read-only and may have an access-time update.

The default text report identifies a successfully published copy and its committed receipt. `--format json` emits an `exacopy.cli.copy` 1.0 summary. The successful summary includes a UUIDv7 job ID, the job directory component, a decimal byte count, the BLAKE3 stream digest, and the committed receipt digest. The receipt represents a live-observed source, independent logical writes and buffered BLAKE3 read-back, and the adapter's basic metadata policy. Durability remains unconfirmed. Check [verified staging](../../../docs/verified-staging.md) and the [Linux adapter](../../../docs/local-adapter.md) for the metadata, barrier, and filesystem evidence limits.

| Exit | Outcome |
| --- | --- |
| 0 | Exclusive publication and committed receipt |
| 2 | Invalid usage or request |
| 3 | Conflict or stale plan |
| 4 | I/O, resource or report failure |
| 5 | Integrity failure |
| 6 | Unsupported platform, required capability or metadata |
| 8 | Profile authorization failed |
| 9 | Publication or its journal evidence requires reconciliation |

If report output fails after publication, the CLI attempts to report the committed job on stderr and exits 4. The copy remains published. CLI process tests cover the report and authorization stringency, exact output content, authenticated job bindings, and exclusive publication under concurrency. These exercise the local portion of R-007–009, R-027–028, R-154 and R-194 and their corresponding acceptance cases. The development CLI and ext4 VM tests carry no release or power-loss qualification.

## Inspect, finish, or retry a retained copy

```sh
cargo run --locked -p exacopy-cli -- recover inspect ./destination/.exacopy-JOB_UUID --profile ./private-profile --format json
cargo run --locked -p exacopy-cli -- recover finish ./destination/.exacopy-JOB_UUID --profile ./private-profile --format json
cargo run --locked -p exacopy-cli -- recover retry ./destination/.exacopy-JOB_UUID --source-root ./source-parent --profile ./private-profile --format json
```

Use the job name from the copy report and the profile that created it. The inspection takes a shared lease, authenticates the owner and plan, validates the accepted journal prefix and available receipt, and checks the current stage and target. A successful check is a current observation. The command is read-only and leaves the job artifacts available for further recovery.

Journaled copies can retain flush-backed measurements of partial ranges in the private job. Inspection checks the range pages referenced by the journal. A job interrupted during staging can report `retained_preparation`. Partial range resumption remains unsupported.

For `published_needs_barriers` or `published_needs_receipt` with a clean journal, `recover finish` takes an exclusive lease, authenticates the same evidence again, and freshly measures the published file. It records a new recovery generation, synchronizes the current publication and missing evidence, and commits the receipt. It reuses a valid existing receipt. Repeating a completed recovery returns the existing completion.

For `possible_retry` with a clean journal, `recover retry` takes an explicit grant for the original source directory. Supply the parent directory you selected when starting the copy. Recovery rereads the current source and retained stage, verifies required metadata, and records a new durable publication intent before an exclusive rename. It completes an already-published copy's receipt under the same lease. A mismatched source grant, identity, metadata, or stream returns `E_SOURCE_MISMATCH` or another integrity or I/O error, depending on the evidence that failed. Conflicts, torn journals, and missing prerequisites remain visible through inspection, with their evidence available for later recovery.

The `exacopy.local_recovery_inspection` JSON schema version `1.0` includes the last accepted journal sequence and byte offset as decimal strings, whether the tail was clean or torn, and the disposition or blocking error. Exit `0` means the committed receipt and current target agree, `3` means an unrelated entry occupies the target, and `9` means the job still needs reconciliation or is in use. Exit `5` indicates invalid integrity evidence and `8` indicates that the supplied profile could not authenticate the job.
