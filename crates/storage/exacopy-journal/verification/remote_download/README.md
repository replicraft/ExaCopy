# Remote-download codec vectors

Run `python3 -B verification/remote_download/reference.py --openssl /path/to/openssl` from this crate. The independent Python encoder and OpenSSL Ed25519 signer reproduce the signed owner, canonical scope and each of the five private payload shapes. The signing seed and payload digests are synthetic fixture inputs. The on-disk frame envelopes are tested separately against the selected exact predecessor.

The P-043 Rust gate exercises the independent fixtures and profile admission. Existing journal tests retain the legacy formats. Boundary fixtures use an independent wider arithmetic oracle, shape mutations, source observation limits and maximum-size valid encodings. The tests exercise codec admission without end-to-end filesystem or replay qualification.

## Required stage bootstrap profile

Run `python3 -B verification/remote_download/bootstrap.py --openssl /path/to/openssl` from this crate to check the signed bootstrap vectors. The fixture uses the exact owner and sequence-one job head of the existing profile as inputs. Python and OpenSSL independently encode and sign the bootstrap and substitution controls. The Rust integration test rebuilds the framed job and compares the signed payload byte for byte.

The required profile accepts frame kind 38 only as the immediate successor to the verified `JobPrepared`. The payload uses deterministic CBOR `{0: 1, 1: 4, 2: body_bytes, 3: signature_bytes}` with a 512-byte cap. Its signature covers the dedicated `ExaCopy/linux-remote-bootstrap/v1` domain with a terminating NUL followed by the canonical CBOR array `[1, 4, body_bytes]`.

The body map contains keys 0 through 6 in order. These bind the signed owner digest, job UUID, entry UUID, selected owner profile, exact sequence-one frame head, Linux device and inode, and the fixed stage directory role 0. Replay requires the same directory in every subsequent `EntryPrepared`. The existing historical reader retains its original profile, vectors and behavior.

The strict replay controls cover fixture trust substitutions, ordering, and every cut of a signed bootstrap, allocation, entry, checkpoint and uncertainty transcript. An oversized declaration is refused at the frame header before any bootstrap payload bytes are read. Replay supplies historical evidence. The application still establishes current filesystem identity, authorization and the required synchronization before effects.
