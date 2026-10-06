"""Pure-stdlib Ed25519 signatures (RFC 8032), no third-party dependency.

Used for two trust anchors in the provenance ledger:

  * a *source* signs every claim payload it submits (register / submit /
    retract / correct). Its public key is carried by the self-attested
    register entry and every later signature is checked against it;
  * the ledger genesis key signs accountability snapshots, so a snapshot can
    be verified on a machine that never had a database connection.

Points are kept in extended twisted-Edwards coordinates (X, Y, Z, T) with the
complete Hisil-Wong-Carter-Dawson addition law. Fixed-base multiplication
(base point only -- key generation and signing) uses a lazily-built 16-ary
lookup table; arbitrary-point multiplication (verification) is plain
double-and-add.
"""
from __future__ import annotations

import hashlib
import os

__all__ = ["generate_key", "public_from_seed", "sign", "verify", "BadSignature"]

b = 256
q = 2 ** 255 - 19
l_ = 2 ** 252 + 27742317777372353535851937790883648493


class BadSignature(Exception):
    """A signature is malformed or does not verify."""


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, q - 2, q)


d = (-121665 * _inv(121666)) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1) % q
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


_B_y = 4 * _inv(5) % q
_B_x = _xrecover(_B_y)
IDENT = (0, 1, 1, 0)  # extended coordinates of the neutral element


def _affine(x: int, y: int):
    return (x % q, y % q, 1, (x * y) % q)


B = _affine(_B_x, _B_y)


def _xadd(P, Q):
    """Complete unified addition in extended coordinates (a = -1)."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % q
    Bb = (Y1 + X1) * (Y2 + X2) % q
    C = (T1 * 2 * d * T2) % q
    Dd = (2 * Z1 * Z2) % q
    E = (Bb - A) % q
    F = (Dd - C) % q
    G = (Dd + C) % q
    H = (Bb + A) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _xdbl(P):
    X1, Y1, Z1, _T1 = P
    A = X1 * X1 % q
    Bb = Y1 * Y1 % q
    C = 2 * Z1 * Z1 % q
    H = A + Bb
    E = (H - (X1 + Y1) * (X1 + Y1)) % q
    G = (A - Bb) % q
    F = (C + G) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def scalarmult(P, e: int):
    """Arbitrary-base scalar multiplication (double-and-add)."""
    Q = IDENT
    while e > 0:
        if e & 1:
            Q = _xadd(Q, P)
        P = _xdbl(P)
        e >>= 1
    return Q


# Lazily built 16-ary table of base-point multiples: _btable[j][n] = n*16^j*B.
_btable_cache = None


def _btable():
    global _btable_cache
    if _btable_cache is None:
        table = []
        base = B  # 16^0 * B
        for _ in range(b // 4):
            multiples = [IDENT]
            for n in range(1, 16):
                multiples.append(_xadd(multiples[-1], base))
            table.append(multiples)
            base = _xdbl(_xdbl(_xdbl(_xdbl(base))))  # 16x for the next digit
        _btable_cache = table
    return _btable_cache


def scalarmult_base(e: int):
    table = _btable()
    Q = IDENT
    j = 0
    while e > 0:
        nib = e & 15
        if nib:
            Q = _xadd(Q, table[j][nib])
        e >>= 4
        j += 1
    return Q


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    return y.to_bytes(b // 8, "little")


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _encodepoint(P) -> bytes:
    X, Y, Z, _T = P
    zi = _inv(Z)
    x = X * zi % q
    y = Y * zi % q
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(bytearray(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8)))


def _decodepoint(s: bytes):
    if len(s) != b // 8:
        raise BadSignature("wrong point length")
    y = sum(2 ** i * _bit(s, i) for i in range(b - 1))
    x = _xrecover(y)
    if (x & 1) != _bit(s, b - 1):
        x = q - x
    P = _affine(x, y)
    if (-x * x + y * y - 1 - d * x * x * y * y) % q != 0:
        raise BadSignature("point not on curve")
    return P


def _clamped_scalar(seed: bytes) -> int:
    h = _H(seed)
    # RFC 8032 clamp: a = 2^254 + sum(2^i * h_i) over bits i = 3..253.
    a = 2 ** (b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, b - 2))
    return a


def public_from_seed(seed: bytes) -> bytes:
    if len(seed) != b // 8:
        raise ValueError("seed must be 32 bytes")
    return _encodepoint(scalarmult_base(_clamped_scalar(seed)))


def generate_key() -> tuple[bytes, bytes]:
    """Return (seed, public_key), each 32 bytes."""
    seed = os.urandom(b // 8)
    return seed, public_from_seed(seed)


def _hint(m: bytes) -> int:
    return int.from_bytes(_H(m), "little")


def sign(seed: bytes, msg: bytes) -> bytes:
    if len(seed) != b // 8:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = _clamped_scalar(seed)
    A = _encodepoint(scalarmult_base(a))
    r = _hint(h[b // 8:] + msg) % l_
    R = _encodepoint(scalarmult_base(r))
    S = _encodeint((r + _hint(R + A + msg) * a) % l_)
    return R + S


def verify(public_key: bytes, msg: bytes, signature: bytes) -> None:
    """Verify or raise BadSignature. Never returns a value."""
    if len(public_key) != b // 8:
        raise BadSignature("wrong public key length")
    if len(signature) != b // 4:
        raise BadSignature("wrong signature length")
    R = _decodepoint(signature[: b // 8])
    A = _decodepoint(public_key)
    S = _decodeint(signature[b // 8:])
    if S >= l_:
        raise BadSignature("S out of range")
    h = _hint(signature[: b // 8] + public_key + msg) % l_
    left = scalarmult_base(S)
    right = _xadd(R, scalarmult(A, h))
    if _encodepoint(left) != _encodepoint(right):
        raise BadSignature("signature does not verify")
