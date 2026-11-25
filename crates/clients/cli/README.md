# ExaCopy command-line interface

The `exacopy` binary compares two regular local storage files on Linux. The default output is human-readable. Exact byte comparison is the default and can be requested explicitly.

```sh
cargo run --locked -p exacopy-cli -- diff ./left ./right
cargo run --locked -p exacopy-cli -- diff /path/to/left /path/to/right --compare bytes --format json
```

Each input may be absolute or relative to the current working directory. The command opens the named parent directory and selects its final filename within that capability. Linux file names are preserved as raw bytes. A trailing separator, a reserved final component, a final symlink, or a non-regular file is refused. A parent path is the directory the caller chose, following ordinary Linux directory resolution. A filename that matches a help flag can be passed after `diff --` or with a leading `./`.

| Exit | Outcome |
| --- | --- |
| 0 | Equal over all bytes of the two recorded extents |
| 1 | A difference in recorded length or byte content |
| 2 | Inconclusive, unsupported platform, invalid usage, or failed output |

The `exacopy.cli.diff` JSON summary has `schema_version` set to `1.0`, `relation` set to `bytes`, a `result` of `equal`, `different`, or `inconclusive`, and a `complete` Boolean for the relation decision. Successful decisions carry `consistency` set to `live_observed`. The lengths and offset are unsigned decimal strings. A first-byte offset is zero-based and establishes inequality. The summary reports a single witness. Inconclusive comparisons include an `error` with a stable code and an explanation. Invocation errors are written to stderr. The paged diff report, shell completions, and generated argument parser are outside this initial command.

The command exercises the byte comparison and exit-status portions of the local CLI design. It has no persistent job, mutation, or publication authority. See the [diff crate](../../operations/diff/README.md) for evidence scope and source-observation limits.
