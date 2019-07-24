import binascii
import hashlib
import hmac
import re

from typing import (
    List,
    NamedTuple,
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

SECP256k1_ORD = SECP256k1.order
SECP256k1_GEN = SECP256k1.generator

PrivateKey = int
PublicKey = Point

ChainCode = bytes
Index = int
Fingerprint = bytes

ExtPrivateKey = Tuple[PrivateKey, ChainCode]
ExtPublicKey = Tuple[PublicKey, ChainCode]

MIN_HARDENED_INDEX = 2 ** 31

BITCOIN_VERSION_BYTES = {
    'mainnet_public': binascii.unhexlify('0488b21e'),
    'mainnet_private': binascii.unhexlify('0488ade4'),
    'testnet_public': binascii.unhexlify('043587cf'),
    'testnet_private': binascii.unhexlify('04358394'),
}

PATH_COMPONENT_RE = re.compile(r'^([0-9]+)(h)?$')


class WalletError(Exception):
    pass


def ser_256(n: int) -> bytes:
    """
    Serialize an unsigned integer ``n`` as 32 bytes (256 bits) in big-endian
    order.
    """
    return n.to_bytes(32, 'big')


def ser_32(n: int) -> bytes:
    """
    Serialize an unsigned integer ``n`` as 4 bytes (32 bits) in big-endian
    order.
    """
    return n.to_bytes(4, 'big')


def parse_256(bs: bytes) -> int:
    """
    Parse an unsigned integer encoded in big-endian order from the length 32
    byte sequence ``bs``.
    """
    assert len(bs) == 32

    return int.from_bytes(bs, 'big')


def ser_p(p: Point) -> bytes:
    """
    Serialize an elliptic curve point ``p`` in compressed form as described in
    SEC1v2 (https://secg.org/sec1-v2.pdf) section 2.3.3.
    """
    x, y = p.x(), p.y()

    if y & 1:
        return b'\x03' + ser_256(x)
    else:
        return b'\x02' + ser_256(x)


def fingerprint_for_prv_key(k: PrivateKey) -> bytes:
    """
    Return fingerprint bytes for the given private key ``k``.
    """
    K = point(k)
    return fingerprint_for_pub_key(K)


def fingerprint_for_pub_key(K: PublicKey) -> bytes:
    """
    Return fingerprint bytes for the given public key point ``K``.
    """
    K_compressed = ser_p(K)

    identifier = hashlib.new(
        'ripemd160',
        hashlib.sha256(K_compressed).digest(),
    ).digest()

    return identifier[:4]


def HMAC_SHA512(key: bytes, data: bytes) -> bytes:
    """
    Return the SHA512 HMAC bytes for the byte sequence ``data`` signed with the
    byte sequence ``key``.
    """
    h = hmac.new(key, data, hashlib.sha512)
    return h.digest()


def point(p: int) -> Point:
    """
    Return the elliptic curve point resulting from multiplication of the
    sec256k1 base point with the integer ``p``.
    """
    return Public_key(SECP256k1_GEN, SECP256k1_GEN * p).point


def CKDpriv(k_par: PrivateKey, c_par: ChainCode, i: Index) -> ExtPrivateKey:
    """
    Return the extended child private key at index ``i`` for the parent private
    key ``k_par`` with chain code ``c_par``.
    """
    if i >= MIN_HARDENED_INDEX:
        # Generate a hardened key
        data = b'\x00' + ser_256(k_par) + ser_32(i)
    else:
        # Generate a non-hardened key
        data = ser_p(point(k_par)) + ser_32(i)

    I = HMAC_SHA512(c_par, data)  # noqa: E741
    I_L, I_R = I[:32], I[32:]

    I_L_as_int = parse_256(I_L)
    k_i = (I_L_as_int + k_par) % SECP256k1_ORD
    c_i = I_R

    if I_L_as_int >= SECP256k1_ORD or k_i == 0:
        raise WalletError('Generated private key is invalid')

    return k_i, c_i


def CKDpub(K_par: PublicKey, c_par: ChainCode, i: Index) -> ExtPublicKey:
    """
    Return the extended child public key at index ``i`` for the parent public
    key ``K_par`` with chain code ``c_par``.
    """
    if i >= MIN_HARDENED_INDEX:
        # Not possible, fail
        raise WalletError('Cannot generate hardened key from public key')
    else:
        # Generate a non-hardened key
        data = ser_p(K_par) + ser_32(i)

    I = HMAC_SHA512(c_par, data)  # noqa: E741
    I_L, I_R = I[:32], I[32:]

    I_L_as_int = parse_256(I_L)
    K_i = point(I_L_as_int) + K_par
    c_i = I_R

    if I_L_as_int >= SECP256k1_ORD or K_i == INFINITY:
        raise WalletError('Generated private key is invalid')

    return K_i, c_i


def N(k: PrivateKey, c: ChainCode) -> ExtPublicKey:
    """
    Return the associated extended public key for the extended private key
    composed of private key ``k`` and chain code ``c``.
    """
    return point(k), c


def get_master_key(bs: bytes) -> ExtPrivateKey:
    """
    Return an extended master key generated from seed bytes ``bs``.
    """
    I = HMAC_SHA512(b'Bitcoin seed', bs)  # noqa: E741

    I_L, I_R = I[:32], I[32:]

    k = parse_256(I_L)
    c = I_R

    if k >= SECP256k1_ORD or k == 0:
        raise WalletError('Generated master key is invalid')

    return k, c


def priv_to_base58(
    network: str,
    depth: int,
    fingerprint: bytes,
    child_number: int,
    chain_code: bytes,
    k: PrivateKey,
) -> str:
    version_bytes = BITCOIN_VERSION_BYTES[network + '_private']
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


def pub_to_base58(
    network: str,
    depth: int,
    fingerprint: bytes,
    child_number: int,
    chain_code: bytes,
    K: PublicKey,
) -> str:
    version_bytes = BITCOIN_VERSION_BYTES[network + '_public']
    depth_byte = depth.to_bytes(1, 'big')
    child_number_bytes = ser_32(child_number)
    key_bytes = ser_p(K)

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


def parse_path(path: str) -> List[int]:
    if path.endswith('/'):
        raise ValueError(f'Path must not end with slash: {repr(path)}')

    path_comps = path.split('/')
    if len(path_comps) < 1:
        raise ValueError(f'Path has no components: {repr(path)}')

    child_comps = path_comps[1:]
    child_nums = []
    for comp in child_comps:
        match = PATH_COMPONENT_RE.match(comp)
        if match is None:
            raise ValueError(f'Invalid path component: {repr(comp)}')

        child_num_str, hardened = match.groups()
        child_num = int(child_num_str)
        if hardened is not None:
            child_nums.append(child_num + MIN_HARDENED_INDEX)
        else:
            child_nums.append(child_num)

    return child_nums


class KeyInfo(NamedTuple):
    ext_pivate: ExtPrivateKey
    ext_public: ExtPublicKey
    depth: int
    parent_fingerprint: Fingerprint
    child_number: Index


def ext_keys_from_path(seed_hex_str: str, path: str) -> KeyInfo:
    seed_bytes = binascii.unhexlify(seed_hex_str)

    ext_master = get_master_key(seed_bytes)
    child_nums = parse_path(path)

    if len(child_nums) == 0:
        # Return info for master keys
        ext_private = ext_master
        ext_public = N(*ext_master)

        return KeyInfo(ext_private, ext_public, 0, b'\x00' * 4, 0)

    k_par, c_par = None, None
    ext_child = ext_master

    for i in child_nums:
        k_par, c_par = ext_child
        ext_child = CKDpriv(k_par, c_par, i)

    ext_private = ext_child
    ext_public = N(*ext_child)

    return KeyInfo(
        ext_private,
        ext_public,
        len(child_nums),
        fingerprint_for_prv_key(k_par),
        child_nums[-1],
    )
