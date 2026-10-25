#!/usr/bin/env python3
import ctypes
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIB_PATH = HERE.parent / "lib" / "libcup2.so"
libcup = ctypes.CDLL(str(LIB_PATH))

libcup.cup_validate_header_and_footer.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint64]
libcup.cup_validate_header_and_footer.restype = ctypes.c_int

libcup.cup_pack_header_and_footer_ext.argtypes = [
    ctypes.c_uint8, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_uint32,
    ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,
    ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_uint32,
    ctypes.c_char_p, ctypes.c_char_p
]
libcup.cup_pack_header_and_footer_ext.restype = ctypes.c_int

libcup.cup_fastcdc_get_static_gear_table.argtypes = []
libcup.cup_fastcdc_get_static_gear_table.restype = ctypes.POINTER(ctypes.c_uint64)

libcup.cup_blake3_256.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p]
libcup.cup_blake3_256.restype = None


def gear_table_reference() -> list:
    """Independently recompute the normative FastCDC Gear table with hashlib:
    gear[b] = SHA-256("CUP-FASTCDC-GEAR-TABLE-V2" || byte(b)) as u64le."""
    table = []
    prefix = b"CUP-FASTCDC-GEAR-TABLE-V2"
    for b in range(256):
        digest = hashlib.sha256(prefix + bytes([b])).digest()
        table.append(int.from_bytes(digest[:8], "little"))
    return table


if __name__ == "__main__":
    hdr = ctypes.create_string_buffer(128)
    ftr = ctypes.create_string_buffer(32)
    rc = libcup.cup_pack_header_and_footer_ext(
        3, 0x0000F1C8, 10000, 9, 704, 1412, 2400, 4096,
        b"glibc-2.38+wl", b"org.cup.Rt/3.0", 2, 3, 1, 12, 0x00060600, hdr, ftr
    )
    assert rc == 0 and libcup.cup_validate_header_and_footer(hdr, ftr, 10000) == 0

    # TV5: full 256-entry Gear-table cross-check against an independent
    # Python-side recomputation (previously only 2 of 256 entries were probed).
    gear = libcup.cup_fastcdc_get_static_gear_table()
    ref = gear_table_reference()
    for idx in range(256):
        assert gear[idx] == ref[idx], f"gear[{idx}] mismatch: {gear[idx]:#x} != {ref[idx]:#x}"

    # BLAKE3-256 known-answer vector: official BLAKE3 hash of the empty input.
    out = ctypes.create_string_buffer(32)
    libcup.cup_blake3_256(None, 0, out)
    kat = bytes.fromhex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    assert out.raw == kat, f"BLAKE3 KAT mismatch: {out.raw.hex()}"

    print("[pycup-ffi] libcup2.so FFI Self-Test PASSED! (header pack/validate, 256/256 Gear entries, BLAKE3 KAT)")
