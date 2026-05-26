"""SM3 cryptographic hash (GB/T 32905-2016) — 国密哈希算法.

SM3 is the Chinese national standard hash function, producing a 256-bit digest.
It is used in combination with SM2 for digital signatures (SM2+SM3) and as a
general-purpose hash for data integrity.

In production (v1.1 + Tongsuo PKCS#11), SM3 operations are performed inside the
HSM. This module provides a software fallback using the `gmssl` or `tongsuopy`
Python packages, or a pure-Python implementation as last resort.

API mirrors hashlib for familiarity:
    >>> sm3_hash(b"hello")  # 256-bit hex digest
    >>> h = SM3()
    >>> h.update(b"hello ")
    >>> h.update(b"world")
    >>> h.digest()
"""

from __future__ import annotations

import struct
from typing import Any


# ---------------------------------------------------------------------------
# Pure-Python SM3 implementation (GB/T 32905-2016)
# Based on the specification: 256-bit output, 512-bit blocks, Merkle-Damgård
# ---------------------------------------------------------------------------


# Initial values (IV) per GB/T 32905-2016 §4.2
_SM3_IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]

# T_j constants: 0 <= j <= 15 uses T1, 16 <= j <= 63 uses T2
_SM3_T1 = 0x79CC4519
_SM3_T2 = 0x7A879D8A


def _rotl(x: int, n: int) -> int:
    """Rotate left: 32-bit unsigned."""
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sm3_ff_j(x: int, y: int, z: int, j: int) -> int:
    """Boolean function FF_j per §4.3."""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _sm3_gg_j(x: int, y: int, z: int, j: int) -> int:
    """Boolean function GG_j per §4.3."""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & 0xFFFFFFFF) & z)


def _sm3_p0(x: int) -> int:
    """Permutation function P0 per §4.4."""
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _sm3_p1(x: int) -> int:
    """Permutation function P1 per §4.4."""
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _sm3_cf(v_i: list[int], b_i: list[int]) -> list[int]:
    """SM3 compression function CF per §5.3."""
    # Message expansion — W and W'
    w = list(b_i)  # W0..W15
    for j in range(16, 68):
        w.append(
            _sm3_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
            ^ _rotl(w[j - 13], 7)
            ^ w[j - 6]
        )

    w1 = [w[j] ^ w[j + 4] for j in range(64)]

    # Compression
    a, b, c, d, e, f, g, h = v_i

    for j in range(64):
        ss1 = _rotl((_rotl(a, 12) + e + _rotl((_SM3_T1 if j < 16 else _SM3_T2), j & 31)) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        tt1 = (_sm3_ff_j(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
        tt2 = (_sm3_gg_j(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
        d = c
        c = _rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _sm3_p0(tt2)

    return [
        (a ^ v_i[0]) & 0xFFFFFFFF,
        (b ^ v_i[1]) & 0xFFFFFFFF,
        (c ^ v_i[2]) & 0xFFFFFFFF,
        (d ^ v_i[3]) & 0xFFFFFFFF,
        (e ^ v_i[4]) & 0xFFFFFFFF,
        (f ^ v_i[5]) & 0xFFFFFFFF,
        (g ^ v_i[6]) & 0xFFFFFFFF,
        (h ^ v_i[7]) & 0xFFFFFFFF,
    ]


class SM3:
    """SM3 hash object (GB/T 32905-2016).

    Usage:
        h = SM3()
        h.update(b"message")
        digest = h.digest()   # 32 bytes
        hexdigest = h.hexdigest()  # 64 hex chars

        # Or one-shot:
        digest = sm3_hash(b"message")
    """

    digest_size: int = 32
    block_size: int = 64

    def __init__(self) -> None:
        self._v = list(_SM3_IV)
        self._buffer = bytearray()
        self._length: int = 0  # Total bytes processed

    def update(self, data: bytes) -> None:
        self._buffer.extend(data)
        self._length += len(data)

        # Process complete 512-bit (64-byte) blocks
        while len(self._buffer) >= 64:
            block = self._buffer[:64]
            del self._buffer[:64]
            self._process_block(block)

    def _process_block(self, block: bytes) -> None:
        """Process one 512-bit block."""
        # Convert block to 16 32-bit words (big-endian)
        w = list(struct.unpack(">16I", block))
        self._v = _sm3_cf(self._v, w)

    def digest(self) -> bytes:
        """Return the 256-bit SM3 digest."""
        # Make a copy so we don't mutate internal state
        v = list(self._v)
        buf = bytearray(self._buffer)
        total_bits = self._length * 8

        # Padding per §5.1: append 1, then 0s, then 64-bit length
        buf.append(0x80)
        while (len(buf) + 8) % 64 != 0:
            buf.append(0x00)

        # Append bit length as 64-bit big-endian
        buf.extend(struct.pack(">Q", total_bits))

        # Process remaining blocks
        for i in range(0, len(buf), 64):
            block = buf[i:i + 64]
            if len(block) < 64:
                block = block + b"\x00" * (64 - len(block))
            w = list(struct.unpack(">16I", bytes(block)))
            v = _sm3_cf(v, w)

        # Output as big-endian bytes
        return struct.pack(">8I", *v)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "SM3":
        new = SM3.__new__(SM3)
        new._v = list(self._v)
        new._buffer = bytearray(self._buffer)
        new._length = self._length
        return new


def sm3_hash(data: bytes) -> bytes:
    """One-shot SM3 hash. Returns 32 bytes."""
    h = SM3()
    h.update(data)
    return h.digest()


def sm3_hexdigest(data: bytes) -> str:
    """One-shot SM3 hash. Returns 64 hex characters."""
    return sm3_hash(data).hex()


def sm3_hmac(key: bytes, data: bytes) -> bytes:
    """HMAC-SM3 (per GB/T 15852.1-2020).

    Standard HMAC construction with SM3 as the underlying hash.
    """
    block_size = 64
    if len(key) > block_size:
        key = sm3_hash(key)

    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))

    o_key_pad = bytes(k ^ 0x5C for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)

    inner = SM3()
    inner.update(i_key_pad + data)
    outer = SM3()
    outer.update(o_key_pad + inner.digest())
    return outer.digest()


# ---------------------------------------------------------------------------
# Hardware-accelerated SM3 (Tongsuo / GmSSL)
# ---------------------------------------------------------------------------


def _try_native_sm3() -> Any | None:
    """Try to import a native SM3 implementation (gmssl or tongsuopy)."""
    for module_name in ("gmssl.sm3", "gmssl", "tongsuopy"):
        try:
            mod = __import__(module_name, fromlist=["sm3_hash"])
            if hasattr(mod, "sm3_hash"):
                return mod.sm3_hash
        except ImportError:
            continue
    return None


_native_sm3 = _try_native_sm3()


def sm3_hash_fast(data: bytes) -> bytes:
    """Use native SM3 if available, otherwise fall back to pure Python."""
    if _native_sm3 is not None:
        return _native_sm3(data)
    return sm3_hash(data)
