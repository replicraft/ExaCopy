# Independent genesis publication intent vectors

`intent.tsv` contains 27 frozen rows. SHA-256 is
`901b8f264c434def8c64216052b22f2225584abab2186c14c873b9fb09798ff3`.
The independent oracle uses Python `struct` and the pinned portable C
BLAKE3 probe with the checked-in exacopy-transfer P-063 `valid` and
`empty` vectors. The adopted intent specification SHA-256 is
`3a5f07a7c55e8ccebb9c95ded2f71b3ec86f3acadfc92dd3b2430f8d1014e6a9`.
The frozen generator SHA-256 is
`8fc164ba191c458df1961af3afb1b6016d078f3d3040c997c79a991702a1f719`.

The owning platform codec test checks canonical wire round trips for both
admitted device cases, parser refusal for the 14 malformed shapes and
selection mismatch for the 11 structurally valid substitutions. It also
derives all 364 shorter prefixes from the canonical row. The offered
binding cases can parse as data and still differ from the independently
selected intent. These are portable intent format controls.
