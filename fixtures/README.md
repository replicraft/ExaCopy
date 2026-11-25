# Shared test fixtures

Only fixtures used by multiple packages live here. Package-specific inputs and
formal-verification artifacts stay with the package that owns the contract.

| Fixture | Provenance and reproduction | Expected properties |
| --- | --- | --- |
| [macOS empty ACL helper](macos/empty_acl.c) | Authored for ExaCopy under the workspace's Apache-2.0 terms. The CLI and transfer tests compile it with the native C compiler and invoke it on a newly created test directory. | Opens only a directory at the final component without following a symlink, sets an empty extended ACL on the held descriptor, and returns a failing exit status if admission or application fails. Native Rust tests check the resulting filesystem behavior. |

The helper generates a synthetic condition. The test harness records whether the
host's APFS fixture meets the selected native profile.
