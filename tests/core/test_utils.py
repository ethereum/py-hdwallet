import pytest

from hdwallet.utils import (
    MIN_HARDENED_INDEX,
    PATH_TYPE_MASTER,
    PATH_TYPE_RELATIVE,
    parse_bip32_path,
)


@pytest.mark.parametrize(
    'path,path_type,parsed',  # type: ignore
    (
        (
            'm',
            PATH_TYPE_MASTER,
            (),
        ),
        (
            'm/0',
            PATH_TYPE_MASTER,
            (0,),
        ),
        (
            'm/0/2147483647h',
            PATH_TYPE_MASTER,
            (0, 2147483647 + MIN_HARDENED_INDEX),
        ),
        (
            'm/0/2147483647h/1',
            PATH_TYPE_MASTER,
            (0, 2147483647 + MIN_HARDENED_INDEX, 1),
        ),
        (
            'm/0/2147483647h/1/2147483646h',
            PATH_TYPE_MASTER,
            (0, 2147483647 + MIN_HARDENED_INDEX, 1, 2147483646 + MIN_HARDENED_INDEX),
        ),
        (
            'm/0/2147483647h/1/2147483646h/2',
            PATH_TYPE_MASTER,
            (0, 2147483647 + MIN_HARDENED_INDEX, 1, 2147483646 + MIN_HARDENED_INDEX, 2),
        ),
        (
            'm/0h',
            PATH_TYPE_MASTER,
            (MIN_HARDENED_INDEX,),
        ),
        (
            'm/0h/1',
            PATH_TYPE_MASTER,
            (MIN_HARDENED_INDEX, 1),
        ),
        (
            'm/0h/1/2h',
            PATH_TYPE_MASTER,
            (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX),
        ),
        (
            'm/0h/1/2h/2',
            PATH_TYPE_MASTER,
            (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX, 2),
        ),
        (
            'm/0h/1/2h/2/1000000000',
            PATH_TYPE_MASTER,
            (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX, 2, 1000000000),
        ),
        (
            'M/0h/1/2h/2',
            PATH_TYPE_MASTER,
            (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX, 2),
        ),
        (
            '0h/1/2h/2',
            PATH_TYPE_RELATIVE,
            (MIN_HARDENED_INDEX, 1, 2 + MIN_HARDENED_INDEX, 2),
        ),
    ),
)
def test_parse_bip32_path_master_paths(path, path_type, parsed):
    assert parse_bip32_path(path, path_type=path_type) == parsed


@pytest.mark.parametrize(
    'path,path_type,match',  # type: ignore
    (
        (
            '',
            'foo',
            'Unrecognized path type'
        ),
        (
            '/m/0/2147483647h/1',
            PATH_TYPE_MASTER,
            'Path must not begin with slash',
        ),
        (
            'm/0/2147483647h/1/',
            PATH_TYPE_MASTER,
            'Path must not end with slash',
        ),
        (
            '',
            PATH_TYPE_MASTER,
            'Master path must begin with'
        ),
        (
            '0/2147483647h',
            PATH_TYPE_MASTER,
            'Master path must begin with',
        ),
        (
            'm/0/2147483647h',
            PATH_TYPE_RELATIVE,
            'Relative path may not begin with'
        ),
        (
            'm/0/2147483647H/1',
            PATH_TYPE_MASTER,
            'Invalid path component'
        ),
        (
            'm/0/asdfasdf/1',
            PATH_TYPE_MASTER,
            'Invalid path component'
        ),
    ),
)
def test_parse_bip32_path_raises_value_errors(path, path_type, match):
    with pytest.raises(ValueError, match=match):
        parse_bip32_path(path, path_type=path_type)
