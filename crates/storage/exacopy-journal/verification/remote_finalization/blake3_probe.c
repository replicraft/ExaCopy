/* Portable C implementation used only for independent fixture generation. */
#include "blake3.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
	blake3_hasher hash;
	uint8_t input[4096];
	uint8_t digest[BLAKE3_OUT_LEN];
	size_t read;

	blake3_hasher_init(&hash);
	while ((read = fread(input, 1, sizeof(input), stdin)) != 0) {
		blake3_hasher_update(&hash, input, read);
	}
	if (ferror(stdin)) {
		return 1;
	}
	blake3_hasher_finalize(&hash, digest, sizeof(digest));
	for (size_t i = 0; i < sizeof(digest); ++i) {
		printf("%02x", digest[i]);
	}
	return putchar('\n') == EOF;
}
