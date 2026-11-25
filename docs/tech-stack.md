# Technical stack

The [workspace manifest](../Cargo.toml) owns dependency selections and
[Cargo.lock](../Cargo.lock) records exact locked versions. The Rust toolchain
is pinned in [rust-toolchain.toml](../rust-toolchain.toml). Native paths follow
the platform contracts linked in the [architecture guide](architecture.md).

| Adopted production dependency | Locked version | Purpose and selection considerations |
| --- | --- | --- |
| `blake3` | 1.8.7 | Stream and stage read-back digests, authenticated record linkage and domain-separated hashes. Any replacement needs algorithm negotiation, independent qualification and a format migration. |
| `crc32c` | 0.6.9 | Fast framing corruption detection. Authentication uses the applicable digest/signature checks. |
| `ed25519-dalek`, `zeroize` | 2.2.0, 1.9.2 | Owner signatures and secret memory cleanup. Use reviewed implementations of these established primitives. |
| `minicbor` | 2.3.1 | Bounded binary records with explicit deterministic CBOR encoding. Generic serialization remains useful for tooling and interchange where its compatibility contract permits it. |
| `serde`, `serde_json` | 1.0.229, 1.0.154 | Typed encodable CLI reports and JSON projections. Private authenticated records use their own bounded binary codecs. |
| `uuid` | 1.29.3 | Typed identifiers with explicit validation and stable byte representation. Callers bind identifiers to the actual capability and attempt. |
| `rustix`, `libc` | 1.1.6, 0.2.191 | Prefer typed OS wrappers where they cover required effects. Keep unsupported native primitives behind reviewed platform-specific bindings. |

The [supply-chain policy](../supply-chain/README.md) describes license, advisory
and audit checks. A production dependency review covers purpose, license,
maintenance and releases, security history, transitive footprint, qualified
OS/architecture, unsafe code, resource behavior, malformed-input handling,
available evidence and replacement options. Assess the standard library,
existing workspace dependencies and established alternatives first.
First-party code uses [Apache-2.0](../LICENSE). Preserve third-party licensing
and notices under the supply-chain policy.

Keep releases locked and use a portable compiler baseline, with reviewed
runtime detection for optional CPU features. The [feature matrix](specs/features/matrix.json) records enabled dependencies,
profiles and target restrictions. The adopted and outstanding release evidence is governed by [Engineering standards](engineering/standards.md).

## Evaluated APFS reader

Pomologie `apfs-reader` 0.1.0 was reviewed at local commit
`78f8586bd87f2b336f2ceeac2f609ec1725bcdfb`. Its manifest declares
`Apache-2.0 AND Unicode-3.0`. Its bounded, offline and read-only image
APIs can provide an independent oracle for admitted files and exact raw
attributes. The mounted ExaCopy adapter requires native descriptor,
lease, dehydration, `F_FULLFSYNC` and exclusive-rename semantics. The
reader stays outside the production dependency graph. Reproduce the review
from `crates/filesystem/apfs-reader/{Cargo.toml,README.md}` at that revision
of the local Pomologie APFS checkout.
