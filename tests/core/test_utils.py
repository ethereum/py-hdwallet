import pytest

from hdwallet.utils import (
    MIN_HARDENED_INDEX,
    parse_bip32_path,
)


@pytest.mark.parametrize(
    'path,parsed',  # type: ignore
    (
        ('m', ()),
        ('m/0', (0,)),
        ('m/0/2147483647h', (0, 2147483647 + MIN_HARDENED_INDEX)),
        ('m/0/2147483647h/1', (0, 2147483647 + MIN_HARDENED_INDEX, 1)),
        ('m/0/2147483647h/1/2147483646h', (0, 2147483647 + MIN_HARDENED_INDEX, 1, 2147483646 + MIN_HARDENED_INDEX)),  # noqa: E501
        ('m/0/2147483647h/1/2147483646h/2', (0, 2147483647 + MIN_HARDENED_INDEX, 1, 2147483646 + MIN_HARDENED_INDEX, 2)),  # noqa: E501
        ('m/0h', (MIN_HARDENED_INDEX,)),
        ('m/0h/1', (MIN_HARDENED_INDEX, 1)),
        ('m/0h/1/2h', (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX)),
        ('m/0h/1/2h/2', (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX, 2)),
        ('m/0h/1/2h/2/1000000000', (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX, 2, 1000000000)),
    ),
)
def test_parse_bip32_path(path, parsed):
    assert parse_bip32_path(path) == parsed
