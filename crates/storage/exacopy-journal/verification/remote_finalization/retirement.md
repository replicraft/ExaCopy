# Independent remote retirement frame fixture

Build the portable BLAKE3 helper in this directory from the lockfile's cached C implementation, as for the existing finalization fixtures. From the crate root, verify the committed synthetic fixture with the same helper and an OpenSSL build that supports Ed25519.

```sh
python3 -B verification/remote_finalization/retirement.py --blake3 /path/to/probe --openssl /path/to/openssl
```

The generator checks the exact existing synthetic owner and reuses its independently encoded first job frame. It builds a new signed bootstrap and drives a separate transcript through allocation, preparation, a nonempty checkpoint, sealing, verification, metadata, kind 39, and the next allocation. The target is a 255-byte raw Unix name. The retirement precedes a fresh stage name and nonce with advancing epochs. Both stage names include a non-UTF-8 byte.

Python creates the deterministic CBOR and independently computes CRC32C and sequence framing. The portable C helper measures the BLAKE3 frame chain. OpenSSL signs the synthetic bootstrap. The Rust fixture checks that the exact kind-39 payload and frame bytes match, that the [1,0,7] profile differs from the prior finalization profile, and that replay retains the old stage while starting the fresh attempt at zero.

The vectors use synthetic facts and do not establish live lease, stage preservation, source authorization or native crash behavior.
