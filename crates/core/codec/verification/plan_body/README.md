# Public Plan v1 canonical body verification

PLN-002 admits the registered 18-field public Plan v1 CBOR body up to 1 MiB. It uses deterministic numeric maps, the original array order, normalized binary timestamps, and the unkeyed BLAKE3 digest of `ExaCopy/plan/v1\0` followed by the exact body bytes. Timestamp construction uses signed Unix seconds and an unsigned fraction from 0 to 999,999,999 nanoseconds.

The codec accepts every registered operation and policy code. It checks the UUIDv7 plan ID, other opaque UUIDs, collection counts, text lengths, resource limits, PlanEntries reference kinds, and their checked advertised count sum. Source-view identity atoms, if present, use the shared profile limit of 1–256 bytes per atom. The 1 MiB total and identity bounds are PLN-002 admission limits. Requested policies and the recorded completeness field are declarations.

Opaque extensions preserve the exact canonical map bytes. Namespace keys at the outer extension map follow the public schema pattern. Values are UTF-8 text, booleans, null, base-CBOR-range integers, or definite arrays and text-keyed maps with the common nesting and count limits. Floating-point numbers, byte strings, tags, indefinite containers, repeated keys, and non-preferred encodings fail admission. Extension values carry no grants or executable meaning.

P-038 covers the R-155 digest-binding lane. The caller supplies the expected digest from its bound parent or previously reviewed body. Page availability, actual descendant item counts, source-view/root binding, identity freshness and approval verification require independent bundle or runtime checks. The codec implements the canonical body and its digest. It carries no native envelope, JSON or RFC3339 parser, approval signature verifier, CLI, or apply authority.

The independent Python recipe emits and reads two canonical bodies. The fixtures exercise populated and null observations, extreme signed timestamps and unsigned counters, multiple document references, protected policy, incomplete enumeration, Unicode text and opaque extensions. The complete body references two independent pages with distinct entries, source and destination paths, and matching source views. Its count and estimate agree with the two leaves. These fixture checks do not add bundle traversal to the production codec. All observations and requested effects are synthetic.

From the codec verification directory, supply the preverified workspace-pinned BLAKE3 C source.

```sh
tmp=$(mktemp -d)
cp manifest/build-hash.sh manifest/hash.c "$tmp"
bash "$tmp/build-hash.sh" "$BLAKE3_C_SOURCE"
python3 -B plan_body/reference.py --hash "$tmp/hash"
```

The verifier compares independently constructed bytes and digests against the stored fixtures. Regenerate with `--write` only after reviewing a wire change.
