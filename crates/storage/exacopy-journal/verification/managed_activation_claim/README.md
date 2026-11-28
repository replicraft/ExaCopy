# Managed activation claim inputs

These are independently constructed fixed-data inputs for the private
496-byte record. The ordinary integration tests import `fixture.rs` from
this directory. P-086 selects only
`managed_activation_claim_matches_frozen_record_and_domain_digest`.

The independent generator used reflected CRC32C with the `123456789`
known answer and BLAKE3 1.0.8 with its empty-input known answer. It used
distinct field patterns and nontrivial little-endian values without
importing production ExaCopy code. The frozen golden checksum bytes are
`bc c7 71 cf`; its domain-separated commitment is
`ea87036b7364e1f320d04fb5df7ce1c2abbd92ab2a3f2cb86ceb699ff6c3811a`.
`commitments.hex` also binds the independently modified valid records.

The fixture helper has a separate CRC32C implementation so malformed-field
tests can reach semantic validation after recomputing the checksum. The
five Rust tests have not been executed by fixture generation. Their
results require an actual run of the integrated revision.

These data do not authenticate a native slot, grant or barrier. See the
[format boundary](../../../../../docs/architecture/managed-activation-claim.md).
