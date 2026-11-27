"""Independent scalar BLAKE3 for bounded, public verification inputs only."""

import struct

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
MASK = 0xFFFFFFFF
START, END, PARENT, ROOT, CONTEXT, MATERIAL = 1, 2, 4, 8, 32, 64
WORDS = struct.Struct("<16I")
CHAIN = struct.Struct("<8I")


def rotate(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & MASK


def mix(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & MASK
    v[d] = rotate(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK
    v[b] = rotate(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & MASK
    v[d] = rotate(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & MASK
    v[b] = rotate(v[b] ^ v[c], 7)


def compress(chain, words, counter, length, flags):
    state = [*chain, *IV[:4], counter & MASK, counter >> 32, length, flags]
    for _ in range(7):
        mix(state, 0, 4, 8, 12, words[0], words[1])
        mix(state, 1, 5, 9, 13, words[2], words[3])
        mix(state, 2, 6, 10, 14, words[4], words[5])
        mix(state, 3, 7, 11, 15, words[6], words[7])
        mix(state, 0, 5, 10, 15, words[8], words[9])
        mix(state, 1, 6, 11, 12, words[10], words[11])
        mix(state, 2, 7, 8, 13, words[12], words[13])
        mix(state, 3, 4, 9, 14, words[14], words[15])
        words = tuple(words[index] for index in PERMUTATION)
    return tuple(state[index] ^ state[index + 8] for index in range(8))


def chunk(data, counter, key, flags):
    chain = key
    last = max(0, ((len(data) - 1) // 64) * 64)
    for offset in range(0, last, 64):
        chain = compress(chain, WORDS.unpack_from(data, offset), counter, 64,
                         flags | (START if offset == 0 else 0))
    tail = data[last:]
    return chain, WORDS.unpack(tail.ljust(64, b"\0")), counter, len(tail), flags | END | (START if last == 0 else 0)


def parent(left, right, key, flags):
    return key, (*left, *right), 0, 64, flags | PARENT


def subtree(data, counter, key, flags):
    if len(data) <= 1024:
        return chunk(data, counter, key, flags)
    # The left subtree contains the largest full power of two strictly below the total.
    left_chunks = 1 << (((len(data) - 1) // 1024).bit_length() - 1)
    cut = 1024 * left_chunks
    left = subtree(data[:cut], counter, key, flags)
    right = subtree(data[cut:], counter + left_chunks, key, flags)
    return parent(compress(*left), compress(*right), key, flags)


def digest(data, key=IV, flags=0):
    if len(data) > 65536:
        raise ValueError("independent BLAKE3 input exceeds the oracle bound")
    chain, words, _, length, final_flags = subtree(data, 0, key, flags)
    return CHAIN.pack(*compress(chain, words, 0, length, final_flags | ROOT))


def derive(context, data):
    key = CHAIN.unpack(digest(context, flags=CONTEXT))
    return digest(data, key, MATERIAL)
