import binascii
import hashlib
import hmac

from typing import (
    Tuple,
)

import base58
from ecdsa import (
    SECP256k1,
)
from ecdsa.ecdsa import (
    Public_key,
)
from ecdsa.ellipticcurve import (
    INFINITY,
    Point,
)

SECP256k1_GEN = SECP256k1.generator

PrivateKey = int
PublicKey = Point

ChainCode = bytes
Index = int

ExtPrivateKey = Tuple[PrivateKey, ChainCode]
ExtPublicKey = Tuple[PublicKey, ChainCode]

MIN_HARDENED_INDEX = 2 ** 31

BITCOIN_VERSION_BYTES = {
    'mainnet_public': binascii.unhexlify('0488b21e'),
    'mainnet_private': binascii.unhexlify('0488ade4'),
    'testnet_public': binascii.unhexlify('043587cf'),
    'testnet_private': binascii.unhexlify('04358394'),
}


class WalletError(Exception):
    pass


def ser_256(n: int) -> bytes:
    return n.to_bytes(32, 'big')


def ser_32(n: int) -> bytes:
    return n.to_bytes(4, 'big')


def parse_256(bs: bytes) -> int:
    return int.from_bytes(bs, 'big')


def ser_p(p: Point) -> bytes:
    x, y = p.x(), p.y()

    if y & 1:
        return b'\x03' + ser_256(x)
    else:
        return b'\x02' + ser_256(x)


def HMAC_SHA512(key: bytes, data: bytes) -> bytes:
    h = hmac.new(key, data, hashlib.sha3_512)
    return h.digest()


def point(p: int) -> Point:
    return Public_key(SECP256k1_GEN, SECP256k1_GEN * p).point


def CKDpriv(k_par: PrivateKey, c_par: ChainCode, i: Index) -> ExtPrivateKey:
    if i >= MIN_HARDENED_INDEX:
        data = b'\x00' + ser_256(k_par) + ser_32(i)
    else:
        data = ser_p(point(k_par)) + ser_32(i)

    I = HMAC_SHA512(c_par, data)  # noqa: E741
    I_L, I_R = I[:32], I[32:]

    parse_256_I_L = parse_256(I_L)
    k_i = (parse_256_I_L + k_par) % SECP256k1.order
    c_i = I_R

    if parse_256_I_L >= SECP256k1.order or k_i == 0:
        raise WalletError('Generated private key is invalid')

    return k_i, c_i


def CKDpub(K_par: PublicKey, c_par: ChainCode, i: Index) -> ExtPublicKey:
    if i >= MIN_HARDENED_INDEX:
        raise WalletError('Cannot generate hardened key from public key')
    else:
        data = ser_p(K_par) + ser_32(i)

    I = HMAC_SHA512(c_par, data)  # noqa: E741
    I_L, I_R = I[:32], I[32:]

    parse_256_I_L = parse_256(I_L)
    K_i = point(parse_256_I_L) + K_par
    c_i = I_R

    if parse_256_I_L >= SECP256k1.order or K_i == INFINITY:
        raise WalletError('Generated private key is invalid')

    return K_i, c_i


def N(k: PrivateKey, c: ChainCode) -> ExtPublicKey:
    return point(k), c


def get_master_key(bs: bytes) -> ExtPrivateKey:
    I = HMAC_SHA512(b'Bitcoin seed', bs)  # noqa: E741

    I_L, I_R = I[:32], I[32:]

    parse_256_I_L = parse_256(I_L)
    k = parse_256_I_L
    c = I_R

    if k >= SECP256k1.order or k == 0:
        raise WalletError('Generated master key is invalid')

    return k, c


def pub_to_base58(
    version: str,
    depth: int,
    fingerprint: bytes,
    child_number: int,
    chain_code: bytes,
    k: PublicKey,
) -> str:
    version_bytes = BITCOIN_VERSION_BYTES[version]
    depth_byte = depth.to_bytes(1, 'big')
    child_number_bytes = ser_32(child_number)
    key_bytes = ser_p(k)

    all_parts = (
        version_bytes,
        depth_byte,
        fingerprint,
        child_number_bytes,
        chain_code,
        key_bytes,
    )
    assert tuple(map(len, all_parts)) == (
        4,  # version bytes
        1,  # depth bytes
        4,  # fingerprint bytes
        4,  # child number bytes
        32,  # chain code bytes
        33,  # key bytes
    )

    all_bytes = b''.join(all_parts)

    return base58.b58encode_check(all_bytes).decode('utf8')


def priv_to_base58(
    version: str,
    depth: int,
    fingerprint: bytes,
    child_number: int,
    chain_code: bytes,
    k: PrivateKey,
) -> str:
    version_bytes = BITCOIN_VERSION_BYTES[version]
    depth_byte = depth.to_bytes(1, 'big')
    child_number_bytes = ser_32(child_number)
    key_bytes = b'\x00' + ser_256(k)

    all_parts = (
        version_bytes,
        depth_byte,
        fingerprint,
        child_number_bytes,
        chain_code,
        key_bytes,
    )
    assert tuple(map(len, all_parts)) == (
        4,  # version bytes
        1,  # depth bytes
        4,  # fingerprint bytes
        4,  # child number bytes
        32,  # chain code bytes
        33,  # key bytes
    )

    all_bytes = b''.join(all_parts)

    return base58.b58encode_check(all_bytes).decode('utf8')
