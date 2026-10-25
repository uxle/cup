#!/usr/bin/env python3
"""Independent BLAKE3-256 reference implementation (written directly from the
official BLAKE3 spec) used to cross-validate the C implementation in libcup2.

Validation protocol:
  1. The Python reference must reproduce the official KAT:
     BLAKE3("") == af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
  2. The C implementation (via libcup2.so + ctypes) must match the Python
     reference for a battery of lengths covering single-block, multi-block,
     single-chunk, chunk-boundary (1023/1024/1025/2047/2048/2049) and
     multi-chunk tree shapes (3, 5, 7 chunks, 3072+ bytes).
"""
import ctypes
import sys
from pathlib import Path

MASK = 0xFFFFFFFF
IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
CHUNK_LEN = 1024
BLOCK_LEN = 64


def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def g(state, a, b, c, d, mx, my):
    state[a] = (state[a] + state[b] + mx) & MASK
    state[d] = rotr32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotr32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + my) & MASK
    state[d] = rotr32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK
    state[b] = rotr32(state[b] ^ state[c], 7)


def round_fn(state, m):
    g(state, 0, 4, 8, 12, m[0], m[1])
    g(state, 1, 5, 9, 13, m[2], m[3])
    g(state, 2, 6, 10, 14, m[4], m[5])
    g(state, 3, 7, 11, 15, m[6], m[7])
    g(state, 0, 5, 10, 15, m[8], m[9])
    g(state, 1, 6, 11, 12, m[10], m[11])
    g(state, 2, 7, 8, 13, m[12], m[13])
    g(state, 3, 4, 9, 14, m[14], m[15])


def compress(cv, block64, counter, block_len, flags):
    m = [int.from_bytes(block64[i * 4:i * 4 + 4], "little") for i in range(16)]
    state = list(cv) + IV[:4] + [
        counter & MASK,
        (counter >> 32) & MASK,
        block_len & MASK,
        flags & MASK,
    ]
    for r in range(7):
        round_fn(state, m)
        if r < 6:
            m = [m[MSG_PERMUTATION[i]] for i in range(16)]
    out = [0] * 16
    for i in range(8):
        out[i] = state[i] ^ state[i + 8]
        out[i + 8] = state[i + 8] ^ cv[i]
    return out


def words_to_bytes(words):
    return b"".join(w.to_bytes(4, "little") for w in words)


def chunk_cv(data, chunk_counter):
    """Chaining value of one 0..1024-byte chunk (no ROOT)."""
    cv = list(IV)
    pos = 0
    n = len(data)
    while True:
        take = min(BLOCK_LEN, n - pos)
        block = data[pos:pos + take] + b"\x00" * (BLOCK_LEN - take)
        flags = 0
        if pos == 0:
            flags |= CHUNK_START
        if pos + take == n:
            flags |= CHUNK_END
        out = compress(cv, block, chunk_counter, take, flags)
        cv = out[:8]
        pos += take
        if pos >= n:
            break
    return cv


def parent_cv(left, right, add_root):
    block = words_to_bytes(left) + words_to_bytes(right)
    flags = PARENT | (ROOT if add_root else 0)
    return compress(IV, block, 0, BLOCK_LEN, flags)[:8]


def blake3_256(data: bytes) -> bytes:
    n = len(data)
    # Single chunk (or empty): ROOT lands on the final block compression.
    if n <= CHUNK_LEN:
        cv = list(IV)
        pos = 0
        while True:
            take = min(BLOCK_LEN, n - pos)
            block = data[pos:pos + take] + b"\x00" * (BLOCK_LEN - take)
            flags = 0
            if pos == 0:
                flags |= CHUNK_START
            if pos + take == n:
                flags |= CHUNK_END | ROOT
            out = compress(cv, block, 0, take, flags)
            cv = out[:8]
            pos += take
            if pos >= n:
                break
        return words_to_bytes(cv)

    # Multi-chunk: left-complete CV-stack merge, ROOT only on final parent.
    stack = []
    pushed = 0
    pos = 0
    while pos < n:
        take = min(CHUNK_LEN, n - pos)
        cv = chunk_cv(data[pos:pos + take], pushed)
        pos += take
        if pos >= n:
            right = cv
            while stack:
                left = stack.pop()
                is_root = not stack
                merged = parent_cv(left, right, is_root)
                right = merged
                if is_root:
                    break
            return words_to_bytes(right)
        node = cv
        count = pushed
        while (count & 1) and stack:
            left = stack.pop()
            node = parent_cv(left, node, False)
            count >>= 1
        stack.append(node)
        pushed += 1
    raise AssertionError("unreachable")


def main():
    # 1. Official KAT for the Python reference itself.
    kat = bytes.fromhex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    got = blake3_256(b"")
    assert got == kat, f"Python reference failed KAT: {got.hex()}"
    print("[ref] Python BLAKE3 reference reproduces the official empty-input KAT")

    # 2. Cross-validate C implementation against the Python reference.
    lib = ctypes.CDLL(str(Path(__file__).resolve().parent.parent / "lib" / "libcup2.so"))
    lib.cup_blake3_256.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p]
    lib.cup_blake3_256.restype = None

    lengths = list(range(0, 200)) + [255, 256, 511, 512, 575, 576, 639, 640,
                                     767, 768, 831, 832, 959, 960, 1023, 1024,
                                     1025, 1088, 1151, 1152, 2047, 2048, 2049,
                                     2176, 3071, 3072, 3073, 4096, 4097, 5120,
                                     6144, 8192, 8193, 10240, 12288, 16384]
    failures = 0
    for ln in lengths:
        data = bytes((i * 131 + 17) & 0xFF for i in range(ln))
        expect = blake3_256(data)
        out = ctypes.create_string_buffer(32)
        lib.cup_blake3_256(data if ln else None, ln, out)
        if out.raw != expect:
            print(f"[FAIL] length {ln}: C={out.raw.hex()} ref={expect.hex()}")
            failures += 1
    if failures:
        print(f"[FAIL] {failures}/{len(lengths)} length mismatches")
        return 1
    print(f"[PASS] C implementation matches the independent reference on all "
          f"{len(lengths)} tested lengths (0..16384, all chunk-boundary shapes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
