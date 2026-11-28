# Managed action preparation inputs

These fixed inputs exercise the proposed private managed ledger origin.
The body is 340 bytes and the common V1 journal frame is 432 bytes.
The origin uses kind 45, sequence 1, and an all-zero predecessor.

| File | Input |
| --- | --- |
| `body.hex` | Exact canonical payload with distinct role and identity patterns, two UUIDv7 values and a full-width little-endian epoch. |
| `frame.hex` | Common envelope, payload, little-endian CRC32C and BLAKE3 record digest. |
| `frame-head.hex` | Independently supplied expected head digest for sequence 1 and exactly 432 physical bytes. |

The independent fixed-data generator used little-endian structured
packing, a reflected Castagnoli CRC and the BLAKE3 1.0.8 reference
package. It checked the CRC32C `123456789` known answer, the BLAKE3
empty-input answer and both existing independent common-frame vectors
in `tests/frame.rs`. It imports no ExaCopy code.

The checksum is `af 80 76 9f`. The recorded head hashes the existing
common frame domain, header, payload and checksum. A consuming test
selects the expected head from the separate fixture, so recomputing a
valid frame with changed content cannot redefine the expected head.

These synthetic inputs establish byte shape only. They carry no
producer authenticity, native slot or ancestry, barrier, live authority
or qualification evidence. No Rust test ran during fixture generation.
