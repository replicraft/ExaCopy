# Public-apply owner vector

Run `python3 -B reference.py --openssl /path/to/openssl` with an OpenSSL
release supporting Ed25519 `pkeyutl -rawin`. The independent Python CBOR
encoder and OpenSSL signer must reproduce the committed hexadecimal fixture
exactly. Its fixed seed is synthetic public test data, never a publisher or
profile credential. Only temporary files are created.

P-040 tests selected-key/profile and signature-domain admission. Ordinary
journal tests additionally cover mutation of each authenticated field,
legacy owner-reader refusal, bounded scalars, expiry ordering and canonical
encoding. Neither result establishes execution or recovery qualification.
