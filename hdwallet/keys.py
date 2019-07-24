"""
Implementations of the functionality defined in BIP32
(https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

This module is meant to implement the functionality laid out in the BIP32
specification in a manner that resembles the notation of that document.  The
hope is that interested viewers will be able to easily use the BIP32 spec as a
reference while reading the code in this module.
"""
import binascii
import re
from typing import (
    cast,
    List,
    NamedTuple,
)

import base58
from ecdsa.ellipticcurve import (
    INFINITY,
)

from .typing import (
    ChainCode,
    Fingerprint,
    Index,
    PublicKey,
    PrivateKey,
)
from .utils import (
    hmac_sha512,
    parse_uint256,
    serialize_curve_point,
    serialize_uint256,
    serialize_uint32,
    SECP256k1_ORD,
    curve_point_from_int,
    fingerprint_from_priv_key,
)

MIN_HARDENED_INDEX = 2 ** 31

BITCOIN_VERSION_BYTES = {
    'mainnet_public': binascii.unhexlify('0488b21e'),
    'mainnet_private': binascii.unhexlify('0488ade4'),
    'testnet_public': binascii.unhexlify('043587cf'),
    'testnet_private': binascii.unhexlify('04358394'),
}

PATH_COMPONENT_RE = re.compile(r'^([0-9]+)(h)?$')


class ExtPrivateKey(NamedTuple):
    k: PrivateKey
    c: ChainCode


class ExtPublicKey(NamedTuple):
    K: PublicKey
    c: ChainCode


class WalletError(Exception):
    pass


def ckd_priv(ext_par: ExtPrivateKey, i: Index) -> ExtPrivateKey:
    """
    Return the child extended private key at index ``i`` for the parent
    extended private key ``ext_par``.

    :param ext_par: The parent extended private key of the child key to be
        generated.
    :param i: The index of the child key to be generated.

    :return: The child extended private key at index ``i`` for the parent
        extended private key ``ext_par``.
    """
    k_par, c_par = ext_par

    if i >= MIN_HARDENED_INDEX:
        # Generate a hardened key
        data = b'\x00' + serialize_uint256(k_par) + serialize_uint32(i)
    else:
        # Generate a non-hardened key
        data = serialize_curve_point(curve_point_from_int(k_par)) + serialize_uint32(i)

    I = hmac_sha512(c_par, data)  # noqa: E741
    I_L, I_R = I[:32], I[32:]

    I_L_as_int = parse_uint256(I_L)
    k_i = (I_L_as_int + k_par) % SECP256k1_ORD
    c_i = I_R

    if I_L_as_int >= SECP256k1_ORD or k_i == 0:
        raise WalletError('Generated private key is invalid')

    return ExtPrivateKey(k_i, c_i)


def ckd_pub(ext_par: ExtPublicKey, i: Index) -> ExtPublicKey:
    """
    Return the child extended public key at index ``i`` for the parent extended
    public key ``ext_par``.

    :param ext_par: The parent extended public key of the child key to be
        generated.
    :param i: The index of the child key to be generated.

    :return: The child extended public key at index ``i`` for the parent
        extended public key ``ext_par``.
    """
    K_par, c_par = ext_par

    if i >= MIN_HARDENED_INDEX:
        # Not possible, fail
        raise WalletError('Cannot generate hardened key from public key')
    else:
        # Generate a non-hardened key
        data = serialize_curve_point(K_par) + serialize_uint32(i)

    I = hmac_sha512(c_par, data)  # noqa: E741
    I_L, I_R = I[:32], I[32:]

    I_L_as_int = parse_uint256(I_L)
    K_i = curve_point_from_int(I_L_as_int) + K_par
    c_i = I_R

    if I_L_as_int >= SECP256k1_ORD or K_i == INFINITY:
        raise WalletError('Generated private key is invalid')

    return ExtPublicKey(K_i, c_i)


def N(ext_k: ExtPrivateKey) -> ExtPublicKey:
    """
    Return the associated extended public key for the extended private key
    ``ext_k``.

    :param ext_k: The extended private key for which an extended public key
        should be generated.

    :return: The associated extended public key for the extended private key
        ``ext_k``.
    """
    k, c = ext_k

    return ExtPublicKey(curve_point_from_int(k), c)


def get_master_key(bs: bytes) -> ExtPrivateKey:
    """
    Return an extended master key generated from seed bytes ``bs``.

    :param bs: The seed bytes to use for master key generation.

    :return: The extended master key resulting from generation with seed bytes
        ``bs``.
    """
    I = hmac_sha512(b'Bitcoin seed', bs)  # noqa: E741

    I_L, I_R = I[:32], I[32:]

    k = parse_uint256(I_L)
    c = I_R

    if k >= SECP256k1_ORD or k == 0:
        raise WalletError('Generated master key is invalid')

    return ExtPrivateKey(k, c)


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
    child_number_bytes = serialize_uint32(child_number)
    key_bytes = b'\x00' + serialize_uint256(k)

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

    return cast(str, base58.b58encode_check(all_bytes).decode('utf8'))


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
    child_number_bytes = serialize_uint32(child_number)
    key_bytes = serialize_curve_point(K)

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

    return cast(str, base58.b58encode_check(all_bytes).decode('utf8'))


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


class ExtKeys(NamedTuple):
    ext_private: ExtPrivateKey
    ext_public: ExtPublicKey
    depth: int
    parent_fingerprint: Fingerprint
    child_number: Index


def ext_keys_from_path(seed_hex_str: str, path: str) -> ExtKeys:
    seed_bytes = binascii.unhexlify(seed_hex_str)
    ext_master = get_master_key(seed_bytes)

    child_nums = parse_path(path)
    if len(child_nums) == 0:
        # Return info for master keys
        ext_private = ext_master
        ext_public = N(ext_master)

        return ExtKeys(ext_private, ext_public, 0, b'\x00' * 4, 0)

    ext_par = None
    ext_child = ext_master
    for i in child_nums:
        ext_par = ext_child
        ext_child = ckd_priv(ext_par, i)

    assert ext_par is not None

    return ExtKeys(
        ext_child,
        N(ext_child),
        len(child_nums),
        fingerprint_from_priv_key(ext_par.k),
        child_nums[-1],
    )
