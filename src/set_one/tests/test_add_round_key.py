import pytest

from set_one.add_round_key import (
    is_equal_to_16_bytes,
    bytes_to_state,
    format_state,
)


def test_is_equal_to_16_bytes():
    assert is_equal_to_16_bytes(b"1234567890123456")  # Exactly 16 bytes
    assert is_equal_to_16_bytes(b"YELLOW SUBMARINE")
    assert not is_equal_to_16_bytes(b"123456789012345")  # 15 bytes
    assert not is_equal_to_16_bytes(b"12345678901234567")  # 17 bytes
    assert not is_equal_to_16_bytes(b"")  # 0 bytes
    assert not is_equal_to_16_bytes(b"1234567890")  # 10 bytes


def test_valid_bytes_to_state():
    # https://www.ascii-code.com/
    assert bytes_to_state(b"AAAAAABAAAAAAAAA") == [
        [65, 65, 65, 65],
        [65, 65, 66, 65],
        [65, 65, 65, 65],
        [65, 65, 65, 65],
    ]
    assert bytes_to_state(b"ZZZZZZBZZZZZZZZZ") == [
        [90, 90, 90, 90],
        [90, 90, 66, 90],
        [90, 90, 90, 90],
        [90, 90, 90, 90],
    ]
    assert bytes_to_state(b"YELLOW SUBMARINE") == [
        [89, 69, 76, 76],
        [79, 87, 32, 83],
        [85, 66, 77, 65],
        [82, 73, 78, 69],
    ]
    assert bytes_to_state(b"1234567890123456") == [
        [49, 50, 51, 52],
        [53, 54, 55, 56],
        [57, 48, 49, 50],
        [51, 52, 53, 54],
    ]


def test_invalid_bytes_to_state():
    with pytest.raises(ValueError, match="Input must be of type 'bytes"):
        bytes_to_state("this is a string")  # Passing a string instead of bytes

    with pytest.raises(ValueError, match="Input must be of type 'bytes"):
        bytes_to_state(1)  # Passing an int instead of bytes

    with pytest.raises(ValueError, match="Input must be exactly 16 bytes long."):
        bytes_to_state(b"1234567890")  # Passing an int instead of bytes


def test_format_state():
    # Input state matrix (4x4)
    state = [
        [0x00, 0x11, 0x22, 0x33],
        [0x44, 0x55, 0x66, 0x77],
        [0x88, 0x99, 0xAA, 0xBB],
        [0xCC, 0xDD, 0xEE, 0xFF],
    ]

    # Expected formatted state matrix
    expected_output = [
        ["00", "11", "22", "33"],
        ["44", "55", "66", "77"],
        ["88", "99", "aa", "bb"],
        ["cc", "dd", "ee", "ff"],
    ]

    # Test that format_state produces the correct output
    assert (
        format_state(state) == expected_output
    ), "The state matrix was not formatted correctly."
