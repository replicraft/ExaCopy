# Detached local public-apply qualification V1

This private record carries no journal frame, feature tag or owner dialect allocation. Its consumer is the default-off Linux SDK qualified staging and historical intent proposal. The [contract inventory](../../specs/contracts/versions.toml) binds its version to the two decimal suffix bytes of the source magic. Existing journal records, ordinary copy, Windows and Darwin owners, and remote qualification and executable digests keep their existing meanings.

## Standalone wire

Exactly 424 bytes. The first 360 are the signed body. Scalar integers are fixed-width little endian. The identity fields carry exact existing 16-byte identifiers in network order. The magic selects V1 and the existing ARM64 Ubuntu ext4 process-crash eligibility profile for one Linux preserve-mode create-new action.

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `EXLPQA01`, selecting V1 and the sole enrolled profile |
| 8 | 16 | Independently configured attestor ID |
| 24 | 32 | Reviewed campaign case-set/scope digest |
| 56 | 32 | Reviewed complete evidence archive digest |
| 88 | 8 | Tested executable extent as u64, 1–512 MiB |
| 96 | 32 | Ordinary BLAKE3-256 of the whole tested executable |
| 128 | 16 | Native boot UUID |
| 144 | 8 | Calling-thread mount namespace ID as u64 |
| 152 | 8 | Same-mount unique ID as u64 |
| 160 | 8 | Exact native device as u64 shared by source and destination |
| 168 | 16 | Source root capability alias |
| 184 | 8 | Source-root inode as u64 on the stated device |
| 192 | 16 | Destination root capability alias |
| 208 | 8 | Destination-root inode as u64 on the stated device |
| 216 | 16 | Ordinary owner profile ID |
| 232 | 32 | Ordinary owner verification key |
| 264 | 32 | Approved public canonical Plan body digest |
| 296 | 16 | Exact leaf entry identity |
| 312 | 32 | Metadata policy digest |
| 344 | 8 | Inclusive nonnegative Unix second as i64 |
| 352 | 8 | Exclusive Unix second as i64, greater than the inclusive second |
| 360 | 64 | Ed25519 signature |

The strict Ed25519 signature covers ASCII `ExaCopy/linux-public-apply-qualification/v1\0` with one NUL, followed by the complete body. No key embedded in the record can select trust. Both externally selected public keys must be strong and canonical, using the existing weak-key predicate and compressed Edwards round-trip equality. The ordinary owner key must differ from the attestor and match the body's exact owner key.

The verified complete record digest is BLAKE3 derive-key with exact context `ExaCopy Linux public apply qualification record v1` over all 424 bytes. The independently selected digest is nonzero and must match. The parser refuses other magic, extent or mandatory structure, including any trailing bytes. It refuses zero attestor ID, scope, evidence, image, Plan, metadata digest, boot UUID, mount namespace, unique mount, root inodes, owner profile and entry. Root aliases use the existing RFC-variant and assigned-version RootCapabilityId predicate. The selected device is checked through the same current native mount and both actual roots. Plan digest and existing stage validation cover the raw names, exact referenced page, approved content and original Plan expiry.

Ordered source and destination roles remain individually checked even if the existing native and Plan policies allow the same physical root or logical alias. A single native device value preserves facts because the evaluated profile requires the same mount. The source profile already enforces exact kernel and mount settings. The attestor's retained evidence archive must cover the build and loaded-code closure. Main image measurement alone supplies no statement about shared libraries, kernel or VM. A configuration lacking independently reviewed provenance remains ineligible.

## Trust and real consumer

The trusted SDK host provisions an attestor key and identity, complete selected record digest, and protected absolute path outside the action request. Pinning the exact record digest makes the reviewed scope/evidence/build/action claims independently selected with no profile wildcard. The existing bounded protected snapshot establishes custody and exact bytes. The application has no technique for proving an arbitrary caller's config came from an administrator. Configuration trust remains a trusted SDK host premise, with no default enrollment and no new CLI route. No test vector is configured operationally.

The SDK verifies the selected signed record before bootstrap and compares it with the admitted Plan, entry, policy, owner key/profile and both actual held root aliases/device/inodes. It measures the exact bounded held running image through protected procfs, compares image extent and digest, then admits the original roots with the existing native profile. The two real observer calls return freshly acquired native tuples only after matching the original eligibility and checking the held executable. The SDK samples UTC internally at preflight and each observer, rejects rollback, applies the inclusive/exclusive attestation window, and checks the original finite Plan deadline through nanoseconds. The engine's existing staging and held-journal checks remain. The actual returned v2 proposal binds the canonical verified record digest and the freshly observed environment. No intent is appended. The already held stage/journal are released at the historical proposal boundary, without a live grant or a live-head claim.

This is one complete staging prerequisite. Checked public apply still needs an independently authorized one-shot live grant, a guarded native no-clobber operation on the original metadata-ready holder, semantic v2 closeout, and exact-build operational evidence. No current native positive can be claimed from the synthetic vectors, x86-64 proposal fixtures or legacy ARM64 history.

## Frozen vectors

The six source fixtures use RFC 8032 section 7.1 public test keys. The retained private generator uses Python fixed-layout encoding, Ed25519 via `cryptography`, and an independent one-chunk BLAKE3 routine checked against the empty-string and `abc` vectors. Data generation did not call existing or proposed Rust code.

| File | Signed contents | Expected Rust result |
| --- | --- | --- |
| accepted | Distinct selected roots, finite image and window, exact signature purpose | Verified pure record |
| wrong-purpose | Same body, separately selected correct complete digest for this specimen, foreign signature purpose | Signature refusal |
| empty-image | Correct signature over zero tested image extent | Record refusal |
| empty-window | Correct signature over equal UTC validity endpoints | Record refusal |
| invalid-root-alias | Correct signature over a source alias outside the existing root UUID contract | Record refusal |
| same-role-key | Correct signature and exact selected bytes, with the attestor also matching the declared and selected owner key | Selection refusal for role reuse |

The pure tests also check exact declared fields, attestor role reuse, wrong complete selection, wrong attestor identity, truncation, trailing bytes, and the two exclusive deadlines. In the existing native public-stage fixture the new SDK refuses the missing-record case before allocating a job, with source bytes/identity and target absence intact. This adds no native selector and executes only where the unchanged feature/profile selects it. The private binding lists the four new pure selectors, compiled under ordinary unit-test cfg and selected by default workspace Nextest. The owned native fixture continues to attest its exact zero-feature test image and existing selector. Only the external SDK re-export needs the existing opt-in feature. No workflow changes are included here.

The sixth vector isolates the signer-role separation check.

## Verification status

Source review, frozen-byte inventory, direct pinned Rustfmt and strict patch replay passed. Compilation, ordinary tests and the native missing-record control remain unverified at this integration revision. No operational enrollment is shipped. The separately retained generator authored data without running the candidate Rust implementation.
