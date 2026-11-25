# Remote-download codec vectors

Run `python3 -B verification/remote_download/reference.py --openssl /path/to/openssl` from this crate. The independent Python encoder and OpenSSL Ed25519 signer reproduce the signed owner, canonical scope and each of the five private payload shapes. The signing seed and payload digests are synthetic fixture inputs. The on-disk frame envelopes are tested separately against the selected exact predecessor.

The P-043 Rust gate exercises the independent fixtures and profile admission. Existing journal tests retain the legacy formats. Boundary fixtures use an independent wider arithmetic oracle, shape mutations, source observation limits and maximum-size valid encodings. The tests exercise codec admission without end-to-end filesystem or replay qualification.
