# References

- [Behavioral reference inventory](specs/compatibility/) tracks applications
  and protocols at the scope actually investigated. Read each entry's
  platform, reference version, oracle and evidence status before making a
  compatibility claim.
- [Engineering standards](engineering/standards.md) records immutable
  source revisions and the adoption and applicability decisions.
- [Contract versioning](architecture/contract-versioning.md) identifies
  owned formats, protocols and current support. [Contract inventory](specs/contracts/versions.toml)
  records implemented version markers.
- [Pomologie APFS reader evaluation](tech-stack.md#evaluated-apfs-reader)
  identifies an offline reference candidate, its exact reviewed revision
  and the native adapter boundary.
- [Foundation](foundation.md), [local adapter](local-adapter.md) and
  [verified staging](verified-staging.md) record the origin and evidence
  of the implemented safety contracts.

External behavior is evidence. The specification, ExaCopy's safety
invariants and independently established correctness determine whether a
behavior should be reproduced. Document intentional deviations with their
acceptance case.
