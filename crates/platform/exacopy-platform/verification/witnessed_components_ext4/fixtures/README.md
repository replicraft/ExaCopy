# Canonical checkpoint component inputs

The storage crate owns the independent canonical codec vectors. The files here are byte-for-byte copies so the native fixture builds with its own package inputs.

| Fixture | Storage owner input | SHA-256 of hex file |
|---|---|---|
| checkpoint-journal.hex | [journal.hex](../../../../../storage/exacopy-journal/tests/remote_continuation/journal.hex) | fa38aa90092b927f9315d6572b6920bff30c216862ad2618d7803105742e3655 |
| checkpoint-successor.hex | [checkpoint.hex](../../../../../storage/exacopy-journal/tests/remote_continuation/checkpoint.hex) | 2c36afd5154e299c6329c8d9e1a012d57f4c0132f5d0e3017857589e496c88c0 |

The known archive ends at byte 2,575 after kind 40 at sequence 6. Its accepted predecessor ends at byte 1,624. The continued range checkpoint is kind 3 at sequence 7, one byte at offset 4, and extends the archive to byte 2,860. The storage crate's [continued checkpoint test](../../../../../storage/exacopy-journal/tests/remote_continued_checkpoint.rs) establishes those canonical range fields. The native component uses exact held journal bytes and EOF to check the supplied vectors.

The component uses actual fixture ext4 eligibility and real native stage, lease, reserved journal, append, file barrier and reread. The archive's logical scope and identities differ from the fixture's native scope. Its canonical bytes and the application callbacks are test inputs, and the test claims no signed current continuation, producer qualification, full SDK, crash or publication evidence.
