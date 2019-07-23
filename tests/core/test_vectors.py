import binascii

from hdwallet.bip32 import (
    get_master_key,
    N,
    priv_to_base58,
    pub_to_base58,
)


def test_master_priv():
    master_seed = binascii.unhexlify('000102030405060708090a0b0c0d0e0f')

    m, c = get_master_key(master_seed)  # noqa: E501
    base58_master = priv_to_base58(
        version='mainnet_private',
        depth=0,
        fingerprint=b'\x00' * 4,
        child_number=0,
        chain_code=c,
        k=m,
    )

    assert base58_master == 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'  # noqa: E501


def test_master_pub():
    master_seed = binascii.unhexlify('000102030405060708090a0b0c0d0e0f')

    ext_master = get_master_key(master_seed)  # noqa: E501
    m, c_priv = ext_master
    M, c_pub = N(m, c_priv)

    assert c_priv == c_pub

    base58_master = pub_to_base58(
        version='mainnet_public',
        depth=0,
        fingerprint=b'\x00' * 4,
        child_number=0,
        chain_code=c_pub,
        K=M,
    )

    assert base58_master == 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'  # noqa: E501
