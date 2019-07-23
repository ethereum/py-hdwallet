import pytest

from hdwallet.bip32 import (
    priv_to_base58,
    pub_to_base58,
    ext_keys_from_path,
)


@pytest.mark.parametrize(
    'seed,path,ext_pub_ser,ext_prv_ser',
    (
        (
            '000102030405060708090a0b0c0d0e0f',
            'm',
            'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',  # noqa: E501
            'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',  # noqa: E501
        ),
        (
            '000102030405060708090a0b0c0d0e0f',
            'm/0h',
            'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',  # noqa: E501
            'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',  # noqa: E501
        ),
        (
            '000102030405060708090a0b0c0d0e0f',
            'm/0h/1',
            'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',  # noqa: E501
            'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',  # noqa: E501
        ),
    ),
)
def test_bip32_test_vectors(seed, path, ext_pub_ser, ext_prv_ser):
    key_info = ext_keys_from_path(seed, path)

    k, c_prv = key_info.ext_pivate
    K, c_pub = key_info.ext_public

    assert c_prv == c_pub

    c = c_prv

    base58_prv = priv_to_base58(
        network='mainnet',
        depth=key_info.depth,
        fingerprint=key_info.parent_fingerprint,
        child_number=key_info.child_number,
        chain_code=c,
        k=k,
    )

    assert base58_prv == ext_prv_ser

    base58_pub = pub_to_base58(
        network='mainnet',
        depth=key_info.depth,
        fingerprint=key_info.parent_fingerprint,
        child_number=key_info.child_number,
        chain_code=c,
        K=K,
    )

    assert base58_pub == ext_pub_ser
