# Linux remote destination qualification record v1

This private record authenticates an independently reviewed destination process-crash campaign. A reader compares the configured attestor and the exact selected build, campaign definition, complete campaign evidence, route profile class and current native facts. The ordinary job-owner key cannot serve as the qualification attestor for that job. The codec accepts signed bytes from independently trusted configuration and has no issuing API.

The route field states which transport profile the campaign exercised. Direct pinned TCP and embedded WireGuard TCP are different classes. The current source authority, endpoint, peer, route revision and host-key pin are checked against the independently selected live scope and signed download owner. The qualification record establishes no source authorization. A fixture signed for an embedded route does not show that any real embedded end-to-end campaign ran.

## Deterministic wire projection

The complete record is at most 3,072 bytes. Its exact CBOR envelope has integer keys in order `{0: 1, 1: 1, 2: body_bstr, 3: attestor_key_bstr32, 4: signature_bstr64}`. The first value selects the wire version. The second selects the qualification attestor role. The Ed25519 signature input is `ExaCopy/linux-remote-destination-qualification/v1` with a terminating NUL followed by canonical CBOR `[1, 1, body_bstr, attestor_key_bstr32]`. The signature is strictly verified under the externally configured nonweak attestor key before decoding the body.

The body is a six-field canonical map.

| Key | Field |
| --- | --- |
| 0 | Nonzero independently selected qualification attestor ID as 16 bytes |
| 1 | Nonzero digest of the exact selected tested build as 32 bytes |
| 2 | Route class 1 for `DirectPinnedTcpV1`, or 2 for `EmbeddedWireGuardTcpV1` |
| 3 | Nonzero digest of the selected campaign definition and scope as 32 bytes |
| 4 | Nonzero digest of the complete reviewed campaign evidence as 32 bytes |
| 5 | Array of exactly 11 native destination fields in the order below |

The facts contain the Linux root identity, effective UID, effective GID, boot UUID, mount namespace inode, ordinary mount ID, unique mount ID, architecture, exact raw kernel release, exact raw kernel build and exact raw mountinfo row. Root identity uses the existing map `{0: 1, 1: device_le_bstr8, 2: inode_le_bstr8, 3: null}`. The boot UUID is 16 raw bytes. The architecture codes 1 and 2 denote x86-64 and AArch64. Each kernel field is limited to 256 bytes and the mountinfo row to 2,048 bytes, excluding delimiters. These byte fields are compared without normalization.

The endpoint projection carries the exact facts and the BLAKE3 digest over `ExaCopy/linux-remote-destination-qualification-record/v1` with its terminating NUL followed by the complete signed record. The native adapter still observes and joins the current kernel, mount, root and credentials under its own constraints. An admitted historical attestation confers no publication permission or power-loss claim.

## Independent vectors

Run `python3 -B verification/remote_download/qualification.py --openssl /path/to/openssl` from this crate. The independent Python CBOR encoder and OpenSSL signer reproduce the synthetic attested records. The Rust controls verify exact trust, scope, destination facts, canonical encoding and bounded decoding. The fixture evidence digests are deliberate test values. These checks do not run a native crash campaign.
