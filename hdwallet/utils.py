import hashlib
import hmac

from ecdsa import (
    SECP256k1,
)
from ecdsa.ecdsa import (
    Public_key,
)
from ecdsa.ellipticcurve import (
    Point,
)

from .typing import (
    PrivateKey,
    PublicKey,
)

SECP256k1_ORD = SECP256k1.order
SECP256k1_GEN = SECP256k1.generator


def curve_point_from_int(p: int) -> Point:
    """
    Return the elliptic curve point resulting from multiplication of the
    sec256k1 base point with the integer ``p``.

    Corresponds directly to the "point" function in the BIP32 spec
    (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#conventions).

    :param p: The integer to multiply with the base point.

    :return: The point resulting from multiplication of the base point with
        ``p``.
    """
    return Public_key(SECP256k1_GEN, SECP256k1_GEN * p).point


def serialize_uint32(n: int) -> bytes:
    """
    Serialize an unsigned integer ``n`` as 4 bytes (32 bits) in big-endian
    order.

    Corresponds directly to the "ser_32(i)" function in the BIP32 spec
    (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#conventions).

    :param n: The integer to be serialized.

    :return: A byte sequence containing the serialization of ``n``.
    """
    return n.to_bytes(4, 'big')


def serialize_uint256(n: int) -> bytes:
    """
    Serialize an unsigned integer ``n`` as 32 bytes (256 bits) in big-endian
    order.

    Corresponds directly to the "ser_256(p)" function in the BIP32 spec
    (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#conventions).

    :param n: The integer to be serialized.

    :return: A byte sequence containing the serialization of ``n``.
    """
    return n.to_bytes(32, 'big')


def serialize_curve_point(p: Point) -> bytes:
    """
    Serialize an elliptic curve point ``p`` in compressed form as described in
    SEC1v2 (https://secg.org/sec1-v2.pdf) section 2.3.3.

    Corresponds directly to the "ser_P(P)" function in the BIP32 spec
    (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#conventions).

    :param p: The elliptic curve point to be serialized.

    :return: A byte sequence containing the serialization of ``p``.
    """
    x, y = p.x(), p.y()

    if y & 1:
        return b'\x03' + serialize_uint256(x)
    else:
        return b'\x02' + serialize_uint256(x)


def parse_uint256(bs: bytes) -> int:
    """
    Parse an unsigned integer encoded in big-endian order from the length 32
    byte sequence ``bs``.

    Corresponds directly to the "parse_256(p)" function in the BIP32 spec
    (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#conventions).

    :param bs: The byte sequence to be parsed.

    :return: The unsigned integer represented by ``bs``.
    """
    assert len(bs) == 32

    return int.from_bytes(bs, 'big')


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    """
    Return the SHA512 HMAC for the byte sequence ``data`` generated with the
    secret key ``key``.

    :param key: The secret key used for HMAC calculation.
    :param data: The data for which an HMAC should be calculated.

    :return: A byte sequence containing the HMAC of ``data`` generated with the
        secret key ``key``.
    """
    h = hmac.new(key, data, hashlib.sha512)
    return h.digest()


def fingerprint_for_prv_key(k: PrivateKey) -> bytes:
    """
    Return fingerprint bytes for the given private key ``k``.

    :param k: The private key for which a fingerprint should be generated.

    :return: A byte sequence containing the fingerprint of ``k``.
    """
    K = curve_point_from_int(k)

    return fingerprint_for_pub_key(K)


def fingerprint_for_pub_key(K: PublicKey) -> bytes:
    """
    Return fingerprint bytes for the given public key point ``K``.

    :param k: The public key for which a fingerprint should be generated.

    :return: A byte sequence containing the fingerprint of ``K``.
    """
    K_compressed = serialize_curve_point(K)

    identifier = hashlib.new(
        'ripemd160',
        hashlib.sha256(K_compressed).digest(),
    ).digest()

    return identifier[:4]
