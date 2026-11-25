#include "blake3.h"
#include <stdio.h>

int main(void) {
    blake3_hasher state;
    blake3_hasher_init(&state);
    unsigned char buffer[4096];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
        blake3_hasher_update(&state, buffer, n);
    }
    if (ferror(stdin)) {
        return 1;
    }
    unsigned char digest[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&state, digest, sizeof(digest));
    for (size_t i = 0; i < sizeof(digest); ++i) {
        printf("%02x", (unsigned)digest[i]);
    }
    return putchar('\n') == EOF ? 1 : 0;
}
