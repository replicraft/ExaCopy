# Initial held Windows bootstrap inspection

This default-off application fixture composes the portable journal codec with
the protected fixed-NTFS record reader. It supports read-side work toward
R-039–041. Windows CLI copy, journal append, published-stage reconciliation
under R-044 and durability qualification remain separate work.

The provisioner exclusively creates a current-user private root, the selected
job and journal directories, and two empty protected record files. It retains
all five native identities before signing. The Rust fixture compares those
identities through the original handles, writes and flushes the two records,
rechecks the identities and closes both writers before inspection.

The reader admits both metadata pins before either data handle. The application
uses the owner bytes and five role values from that same holder with an
independently selected profile, job, root and RFC 8032 test key. It reports a
historical head only after portable inspection and the segment's native
`finish()` both succeed. A byte limiter or cached logical EOF cannot replace
the final held EOF probes and namespace/security rechecks.

The initial native case checks the accepted sole bootstrap, a high-bit change
to the independently selected root serial, and a wrong selected verification
key. It does not close the full native matrix for copied records, hard links,
ADS/ACL changes, rebinding, torn records or terminal I/O failure. Portable
codec controls and earlier component profiles retain their own narrower scope.

The reader requires a stable non-elevated primary user token, a fixed local
NTFS volume and its existing strict ancestor policy. Provisioning excludes
retained untrusted mutation capabilities. Trusted administrators and same-user
participants must refrain from mutations throughout inspection. Share flags
alone do not exclude security, attribute or stream writers.

The `windows-bootstrap-fixture` feature enables the explicit ignored test
target `windows_bootstrap`. `run.ps1` accepts a separately selected exact test
image and digest, uses owned process supervision, and removes the fixture only
after confirmed drain and exact custody checks. Incomplete custody retains
the named evidence. Native compilation and execution of this initial fixture
remain pending. No public command or ordinary feature default is changed.
