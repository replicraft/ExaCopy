# Public PlanEntries leaf verification

This gate exercises the registered public `DocumentRef` and a single v1 `plan_entries` leaf for a regular-file `create_new` observation. The leaf contains two root-relative Unix basenames, one unnamed BLAKE3-256 stream, expected destination absence, and an optional opaque source identity. Each identity atom is limited to 256 bytes in this profile. The page holds one entry and no children. Root IDs remain opaque and require independent capability binding.

P-037 exercises the public page domain admission in R-193/A-193. The tests use both valid independent vectors and negative inputs for kind, digest, byte length, item count, encoding and action. This gate covers the supported leaf and reference codecs. The public Plan envelope, multi-level page traversal, approvals, and apply are outside the gate.

The two fixture pairs derive from the numeric projection in the project's public record registry. The independent Python encoder and parser are shared with the manifest fixture recipe. BLAKE3 runs through the portable C implementation from the workspace-pinned crate source. The empty-file vector carries a real entry, and the optional Linux identity vector preserves exact opaque bytes including a NUL byte.

From the codec verification directory, provide the preverified `blake3-1.8.7/c` source directory.

```sh
tmp=$(mktemp -d)
cp manifest/build-hash.sh manifest/hash.c "$tmp"
bash "$tmp/build-hash.sh" "$BLAKE3_C_SOURCE"
python3 -B plan_entries/reference.py --hash "$tmp/hash"
```

The verifier compares freshly computed canonical bytes to the stored vectors. To regenerate the stored vector files after an approved wire change, add `--write` and review the diff.
