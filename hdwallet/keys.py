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


class KeyGenerationError(Exception):
    pass


class ExtPrivateKey:
    __slots__ = ('private_key', 'chain_code')

    private_key: PrivateKey
    chain_code: ChainCode

    def __init__(self, private_key: PrivateKey, chain_code: ChainCode) -> None:
        self.private_key = private_key
        self.chain_code = chain_code

    @classmethod
    def master_from_hexstr(cls, hexstr: str) -> 'ExtPrivateKey':
        """
        Return an extended master key generated from seed bytes encoded in the
        hex string ``hexstr``.

        :param hexstr: The hexstr that represents the seed bytes to use for
            master key generation.

        :return: The extended master key resulting from generation with seed
            bytes encoded in ``hexstr``.
        """
        seed_bytes = binascii.unhexlify(hexstr)

        return cls.master_from_bytes(seed_bytes)

    @classmethod
    def master_from_bytes(cls, bs: bytes) -> 'ExtPrivateKey':
        """
        Return an extended master key generated from seed bytes ``bs``.

        :param bs: The seed bytes to use for master key generation.

        :return: The extended master key resulting from generation with seed bytes
            ``bs``.
        """
        I = hmac_sha512(b'Bitcoin seed', bs)  # noqa: E741
        I_L, I_R = I[:32], I[32:]

        private_key = parse_uint256(I_L)
        chain_code = I_R

        if private_key >= SECP256k1_ORD or private_key == 0:
            raise KeyGenerationError('Generated master key is invalid')

        return cls(private_key, chain_code)

    def child_ext_private_key(self, i: Index) -> 'ExtPrivateKey':
        """
        Return the child extended private key at index ``i`` for an extended
        private key.

        :param i: The index of the child key to be generated.

        :return: The child extended private key at index ``i`` for an extended
            private key.
        """
        private_key_par, chain_code_par = self.private_key, self.chain_code

        if i >= MIN_HARDENED_INDEX:
            # Generate a hardened key
            data = b'\x00' + serialize_uint256(private_key_par) + serialize_uint32(i)
        else:
            # Generate a non-hardened key
            data = serialize_curve_point(
                curve_point_from_int(private_key_par),
            ) + serialize_uint32(i)

        I = hmac_sha512(chain_code_par, data)  # noqa: E741
        I_L, I_R = I[:32], I[32:]

        I_L_as_int = parse_uint256(I_L)
        private_key_i = (I_L_as_int + private_key_par) % SECP256k1_ORD
        chain_code_i = I_R

        if I_L_as_int >= SECP256k1_ORD or private_key_i == 0:
            raise KeyGenerationError('Generated private key is invalid')

        return type(self)(private_key_i, chain_code_i)

    @property
    def ext_public_key(self) -> 'ExtPublicKey':
        """
        Return the associated extended public key for the extended private key
        ``ext_k``.

        :param ext_k: The extended private key for which an extended public key
            should be generated.

        :return: The associated extended public key for the extended private key
            ``ext_k``.
        """
        private_key, chain_code = self.private_key, self.chain_code

        return ExtPublicKey(curve_point_from_int(private_key), chain_code)


class ExtPublicKey:
    __slots__ = ('public_key', 'chain_code')

    public_key: PublicKey
    chain_code: ChainCode

    def __init__(self, public_key: PublicKey, chain_code: ChainCode):
        self.public_key = public_key
        self.chain_code = chain_code

    def child_ext_public_key(self, i: Index) -> 'ExtPublicKey':
        """
        Return the child extended public key at index ``i`` for an extended
        public key.

        :param i: The index of the child key to be generated.

        :return: The child extended public key at index ``i`` for an extended
            public key.
        """
        public_key_par, chain_code_par = self.public_key, self.chain_code

        if i >= MIN_HARDENED_INDEX:
            # Not possible, fail
            raise KeyGenerationError('Cannot generate hardened key from public key')
        else:
            # Generate a non-hardened key
            data = serialize_curve_point(public_key_par) + serialize_uint32(i)

        I = hmac_sha512(chain_code_par, data)  # noqa: E741
        I_L, I_R = I[:32], I[32:]

        I_L_as_int = parse_uint256(I_L)
        public_key_i = curve_point_from_int(I_L_as_int) + public_key_par
        chain_code_i = I_R

        if I_L_as_int >= SECP256k1_ORD or public_key_i == INFINITY:
            raise KeyGenerationError('Generated private key is invalid')

        return type(self)(public_key_i, chain_code_i)


def priv_to_base58(
    network: str,
    depth: int,
    fingerprint: bytes,
    child_number: int,
    chain_code: bytes,
    private_key: PrivateKey,
) -> str:
    version_bytes = BITCOIN_VERSION_BYTES[network + '_private']
    depth_byte = depth.to_bytes(1, 'big')
    child_number_bytes = serialize_uint32(child_number)
    key_bytes = b'\x00' + serialize_uint256(private_key)

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
    public_key: PublicKey,
) -> str:
    version_bytes = BITCOIN_VERSION_BYTES[network + '_public']
    depth_byte = depth.to_bytes(1, 'big')
    child_number_bytes = serialize_uint32(child_number)
    key_bytes = serialize_curve_point(public_key)

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
    ext_master = ExtPrivateKey.master_from_hexstr(seed_hex_str)

    child_nums = parse_path(path)
    if len(child_nums) == 0:
        # Return info for master keys
        return ExtKeys(
            ext_master,
            ext_master.ext_public_key,
            0,
            b'\x00' * 4,
            0,
        )

    ext_par = None
    ext_child = ext_master
    for i in child_nums:
        ext_par = ext_child
        ext_child = ext_par.child_ext_private_key(i)

    assert ext_par is not None

    return ExtKeys(
        ext_child,
        ext_child.ext_public_key,
        len(child_nums),
        fingerprint_from_priv_key(ext_par.private_key),
        child_nums[-1],
    )
