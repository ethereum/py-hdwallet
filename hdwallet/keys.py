import abc
import binascii
from typing import (
    Any,
    Optional,
    cast,
)

import base58
from ecdsa.ellipticcurve import (
    INFINITY,
)

from .exceptions import (
    KeyGenerationError,
)
from .typing import (
    ChainCode,
    Fingerprint,
    Identifier,
    Index,
    PrivateKey,
    PublicKey,
)
from .utils import (
    MIN_HARDENED_INDEX,
    PATH_TYPE_ABSOLUTE,
    PATH_TYPE_RELATIVE,
    SECP256k1_ORD,
    curve_point_from_int,
    fingerprint_from_priv_key,
    fingerprint_from_pub_key,
    hmac_sha512,
    identifier_from_priv_key,
    identifier_from_pub_key,
    parse_bip32_path,
    parse_uint256,
    serialize_curve_point,
    serialize_uint32,
    serialize_uint256,
)

BITCOIN_VERSION_BYTES = {
    'mainnet_public': binascii.unhexlify('0488b21e'),
    'mainnet_private': binascii.unhexlify('0488ade4'),
    'testnet_public': binascii.unhexlify('043587cf'),
    'testnet_private': binascii.unhexlify('04358394'),
}


class ExtPrivateKey:
    """
    A class to represent the key/chain-code tuple of an extended private key in
    a wallet hierarchy.  Can represent the master extended private key or any
    child extended private key.
    """
    __slots__ = ('private_key', 'chain_code')

    private_key: PrivateKey
    chain_code: ChainCode

    def __init__(self, private_key: PrivateKey, chain_code: ChainCode) -> None:
        self.private_key = private_key
        """
        The integer value of the ECC private key contained in an extended
        private key.
        """

        self.chain_code = chain_code
        """
        The bytes of an extended private key's chain code.
        """

    @classmethod
    def master_from_hexstr(cls, hexstr: str) -> 'ExtPrivateKey':
        """
        Return an extended master key generated from seed bytes encoded in the
        hex string ``hexstr``.

        :param hexstr: A string containing a hex representation of the seed
            bytes to use for master key generation.

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
        hmac_bytes = hmac_sha512(b'Bitcoin seed', bs)
        L, R = hmac_bytes[:32], hmac_bytes[32:]

        private_key = parse_uint256(L)
        chain_code = R

        if private_key >= SECP256k1_ORD or private_key == 0:
            raise KeyGenerationError('Generated master private key is outside acceptable range')

        return cls(private_key, chain_code)

    def child_ext_private_key(self, i: Index) -> 'ExtPrivateKey':
        """
        Return the child extended private key at index ``i`` for a parent
        extended private key instance.

        :param i: The index of the child key to be generated.

        :return: The child extended private key at index ``i`` for a parent
            extended private key instance.
        """
        if i >= MIN_HARDENED_INDEX:
            # Generate a hardened key
            data = b'\x00' + serialize_uint256(self.private_key) + serialize_uint32(i)
        else:
            # Generate a non-hardened key
            data = serialize_curve_point(
                curve_point_from_int(self.private_key),
            ) + serialize_uint32(i)

        hmac_bytes = hmac_sha512(self.chain_code, data)
        L, R = hmac_bytes[:32], hmac_bytes[32:]

        L_as_int = parse_uint256(L)
        private_key_i = (L_as_int + self.private_key) % SECP256k1_ORD
        chain_code_i = R

        if L_as_int >= SECP256k1_ORD or private_key_i == 0:
            raise KeyGenerationError('Generated child private key is outside acceptable range')

        return type(self)(private_key_i, chain_code_i)

    @property
    def ext_public_key(self) -> 'ExtPublicKey':
        """
        The associated extended public key for an extended private key.
        """
        return ExtPublicKey(curve_point_from_int(self.private_key), self.chain_code)

    @property
    def identifier(self) -> Identifier:
        """
        The identifier bytes for an extended private key as described in BIP32
        (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers).
        """
        return identifier_from_priv_key(self.private_key)

    @property
    def fingerprint(self) -> Fingerprint:
        """
        The fingerprint bytes for an extended private key as described in BIP32
        (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers).
        """
        return fingerprint_from_priv_key(self.private_key)


class ExtPublicKey:
    """
    A class to represent the key/chain-code tuple of an extended public key in
    a wallet hierarchy.  Can represent the master extended public key or any
    child extended public key.
    """
    __slots__ = ('public_key', 'chain_code')

    public_key: PublicKey
    chain_code: ChainCode

    def __init__(self, public_key: PublicKey, chain_code: ChainCode):
        self.public_key = public_key
        """
        The curve point value of the ECC public key contained in an extended
        public key.
        """

        self.chain_code = chain_code
        """
        The bytes of an extended public key's chain code.
        """

    def child_ext_public_key(self, i: Index) -> 'ExtPublicKey':
        """
        Return the child extended public key at index ``i`` for a parent
        extended public key instance.

        :param i: The index of the child key to be generated.

        :return: The child extended public key at index ``i`` for the parent
            extended public key instance.
        """
        if i >= MIN_HARDENED_INDEX:
            # Not possible, fail
            raise KeyGenerationError('Cannot generate hardened key from public key')
        else:
            # Generate a non-hardened key
            data = serialize_curve_point(self.public_key) + serialize_uint32(i)

        hmac_bytes = hmac_sha512(self.chain_code, data)
        L, R = hmac_bytes[:32], hmac_bytes[32:]

        L_as_int = parse_uint256(L)
        public_key_i = curve_point_from_int(L_as_int) + self.public_key
        chain_code_i = R

        if L_as_int >= SECP256k1_ORD or public_key_i == INFINITY:
            raise KeyGenerationError('Generated child public key is outside acceptable range')

        return type(self)(public_key_i, chain_code_i)

    @property
    def identifier(self) -> Identifier:
        """
        The identifier bytes for an extended public key as described in BIP32
        (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers).
        """
        return identifier_from_pub_key(self.public_key)

    @property
    def fingerprint(self) -> Fingerprint:
        """
        The fingerprint bytes for an extended public key as described in BIP32
        (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers).
        """
        return fingerprint_from_pub_key(self.public_key)


class WalletNode(abc.ABC):
    """
    Base class for classes that represent extended private or public keys
    located somewhere in an HD wallet's hierarchy.
    """
    __slots__ = ('depth', 'parent_fingerprint', 'child_number', 'parent')

    depth: int
    parent_fingerprint: Fingerprint
    child_number: Index
    parent: Optional['WalletNode']

    def __init__(self, *,
                 depth: int,
                 parent_fingerprint: Fingerprint,
                 child_number: Index,
                 parent: 'WalletNode' = None) -> None:
        self.depth = depth
        """
        The zero-indexed depth at which a node's extended key was generated in
        a wallet hierarchy.  For master keys, this value will be zero.  For
        children of master keys, it will be one, etc.
        """

        self.parent_fingerprint = parent_fingerprint
        """
        The four byte fingerprint of the key from which a node's extended key
        was generated.  For master keys, this value will be four zero-bytes.
        """

        self.child_number = child_number
        """
        The zero-indexed child number of a node's extended key.  This
        identifies the branch taken to generate a node's extended key under its
        parent node.  For master keys, this value will be zero.
        """

        self.parent = parent
        """
        If present, the parent wallet node from which a wallet node was
        generated.  For master keys, or keys loaded from a serialized format,
        this value will be ``None``.
        """

    @abc.abstractproperty
    def serialized_key_bytes(self) -> bytes:
        """
        Serialized bytes for a wallet node's private or public key.  Used in
        the node's base58 serialization.
        """
        pass

    @abc.abstractproperty
    def chain_code(self) -> bytes:
        """
        The chain code for a wallet node's extended private or public key.
        """
        pass

    def to_base58(self, network: str) -> str:
        """
        Return the base58 serialization of a wallet node.

        :param network: The label of the network for which the serialized key
            is valid.

        :return: A string containing the base58 serialization of a wallet node.
        """
        version_bytes = BITCOIN_VERSION_BYTES[network]
        depth_byte = self.depth.to_bytes(1, 'big')
        child_number_bytes = serialize_uint32(self.child_number)
        chain_code = self.chain_code
        key_bytes = self.serialized_key_bytes

        all_parts = (
            version_bytes,
            depth_byte,
            self.parent_fingerprint,
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


class PrivateWalletNode(WalletNode):
    """
    A class that represents an extended private key located somewhere in an HD
    wallet's hierarchy.
    """
    __slots__ = ('ext_private_key',)

    ext_private_key: ExtPrivateKey

    def __init__(self, *, ext_private_key: ExtPrivateKey, **kwargs: Any) -> None:
        self.ext_private_key = ext_private_key

        super().__init__(**kwargs)

    @property
    def serialized_key_bytes(self) -> bytes:
        """
        Serialized bytes for a private wallet node's private key.  Used in the
        node's base58 serialization.
        """
        return b'\x00' + serialize_uint256(self.ext_private_key.private_key)

    @property
    def chain_code(self) -> bytes:
        """
        The chain code of a private wallet node's extended private key.
        """
        return self.ext_private_key.chain_code

    def child_private_wallet_node(self, i: Index) -> 'PrivateWalletNode':
        """
        Return the child private wallet node at index ``i`` for a parent wallet
        node.

        :param i: The index of the child private wallet node.

        :return: The child private wallet node at index ``i`` for a parent
            wallet node.
        """
        child_ext_private_key = self.ext_private_key.child_ext_private_key(i)
        fingerprint = self.ext_private_key.fingerprint

        return type(self)(
            ext_private_key=child_ext_private_key,
            depth=self.depth + 1,
            parent_fingerprint=fingerprint,
            child_number=i,
            parent=self,
        )

    def child_from_path(self, path: str) -> 'PrivateWalletNode':
        """
        Return the child private wallet node located at the given absolute or
        relative path for a parent private wallet node.  If a parent private
        wallet node is the master private wallet node, then the given path must
        be absolute (it must begin with "m" or "M").

        :param path: The path of the child wallet node.

        :return: The child wallet node located at the given path.
        """
        if self.depth == 0:
            child_numbers = parse_bip32_path(path, path_type=PATH_TYPE_ABSOLUTE)
        else:
            child_numbers = parse_bip32_path(path, path_type=PATH_TYPE_RELATIVE)

        child_node = self
        for i in child_numbers:
            child_node = child_node.child_private_wallet_node(i)

        return child_node

    @classmethod
    def master_from_ext_private_key(
        cls,
        ext_private_key: ExtPrivateKey,
    ) -> 'PrivateWalletNode':
        """
        Return a master private wallet node created from an extended private
        key.

        :param ext_private_key: The extended private key to use when creating
            the wallet node.

        :return: A master private wallet node.
        """
        return cls(
            ext_private_key=ext_private_key,
            depth=0,
            parent_fingerprint=b'\x00' * 4,
            child_number=0,
        )

    @classmethod
    def master_from_bytes(cls, bs: bytes) -> 'PrivateWalletNode':
        ext_private_key = ExtPrivateKey.master_from_bytes(bs)

        return cls.master_from_ext_private_key(ext_private_key)

    @classmethod
    def master_from_hexstr(cls, seed_hex_str: str) -> 'PrivateWalletNode':
        ext_private_key = ExtPrivateKey.master_from_hexstr(seed_hex_str)

        return cls.master_from_ext_private_key(ext_private_key)

    @property
    def public_wallet_node(self) -> 'PublicWalletNode':
        """
        The public wallet node corresponding to a private wallet node.
        """
        return PublicWalletNode(
            ext_public_key=self.ext_private_key.ext_public_key,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            parent=self.parent,
        )


class PublicWalletNode(WalletNode):
    """
    A class that represents an extended public key located somewhere in an HD
    wallet's hierarchy.
    """
    __slots__ = ('ext_public_key',)

    ext_public_key: ExtPublicKey

    def __init__(self, *, ext_public_key: ExtPublicKey, **kwargs: Any) -> None:
        self.ext_public_key = ext_public_key

        super().__init__(**kwargs)

    @property
    def serialized_key_bytes(self) -> bytes:
        """
        Serialized bytes for a public wallet node's public key.  Used in the
        node's base58 serialization.
        """
        return serialize_curve_point(self.ext_public_key.public_key)

    @property
    def chain_code(self) -> bytes:
        """
        The chain code of a public wallet node's extended public key.
        """
        return self.ext_public_key.chain_code

    def child_public_wallet_node(self, i: Index) -> 'PublicWalletNode':
        """
        Return the child public wallet node at index ``i`` for a parent wallet
        node.

        :param i: The index of the child public wallet node.

        :return: The child public wallet node at index ``i`` for a parent
            wallet node.
        """
        child_ext_public_key = self.ext_public_key.child_ext_public_key(i)
        fingerprint = self.ext_public_key.fingerprint

        return type(self)(
            ext_public_key=child_ext_public_key,
            depth=self.depth + 1,
            parent_fingerprint=fingerprint,
            child_number=i,
            parent=self,
        )

    def child_from_path(self, path: str) -> 'PublicWalletNode':
        """
        Return the child public wallet node located at the given absolute or
        relative path for a parent public wallet node.  If a parent public
        wallet node is the master public wallet node, then the given path must
        be absolute (it must begin with "m" or "M").

        :param path: The path of the child wallet node.

        :return: The child wallet node located at the given path.
        """
        if self.depth == 0:
            child_numbers = parse_bip32_path(path, path_type=PATH_TYPE_ABSOLUTE)
        else:
            child_numbers = parse_bip32_path(path, path_type=PATH_TYPE_RELATIVE)

        child_node = self
        for i in child_numbers:
            child_node = child_node.child_public_wallet_node(i)

        return child_node
