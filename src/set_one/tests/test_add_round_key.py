import pytest

from set_one.add_round_key import (
    is_equal_to_16_bytes,
    bytes_to_state,
    format_state,
    add_round_key,
)


def test_is_equal_to_16_bytes():
    assert is_equal_to_16_bytes(b"YELLOW SUBMARINE")  # Exactly 16 bytes
    assert is_equal_to_16_bytes(b"1234567890123456")  # Exactly 16 bytes
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


def test_add_round_key_case_one():
    # Test Case 1: Given initial state and round key
    state = [
        [50, 136, 49, 224],  # 0x32, 0x88, 0x31, 0xE0
        [67, 90, 49, 55],  # 0x43, 0x5A, 0x31, 0x37
        [246, 48, 152, 7],  # 0xF6, 0x30, 0x98, 0x07
        [168, 141, 162, 52],  # 0xA8, 0x8D, 0xA2, 0x34
    ]

    round_key = [
        [43, 40, 171, 9],  # 0x2B, 0x28, 0xAB, 0x09
        [126, 174, 247, 207],  # 0x7E, 0xAE, 0xF7, 0xCF
        [21, 210, 21, 79],  # 0x15, 0xD2, 0x15, 0x4F
        [22, 166, 136, 60],  # 0x16, 0xA6, 0x88, 0x3C
    ]

    expected_state = [
        [25, 160, 154, 233],  # Row 0
        [61, 244, 198, 248],  # Row 1
        [227, 226, 141, 72],  # Row 2
        [190, 43, 42, 8],  # Row 3
    ]

    # Perform the AddRoundKey operation for Test Case 1
    add_round_key(state, round_key)
    print("Test Case 1 - Computed state:", state)
    assert state == expected_state, "Test Case 1 failed."


def test_add_round_key_returns_same_state():
    state = [
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        [9, 10, 11, 12],
        [13, 14, 15, 16],
    ]

    round_key = [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
    ]

    expected_state = state.copy()  # Should remain the same

    # Perform the AddRoundKey operation for Test Case 2
    add_round_key(state, round_key)
    print("Test Case 2 - Computed state:", state)
    assert state == expected_state, "Test Case 2 failed."


def test_add_round_key_max_value():
    # Test Case 3: All bits set (maximum value)
    state = [
        [255, 255, 255, 255],
        [255, 255, 255, 255],
        [255, 255, 255, 255],
        [255, 255, 255, 255],
    ]

    round_key = [
        [255, 255, 255, 255],
        [255, 255, 255, 255],
        [255, 255, 255, 255],
        [255, 255, 255, 255],
    ]

    expected_state = [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
    ]  # XORing with 255 results in 0

    # Perform the AddRoundKey operation for Test Case 3
    add_round_key(state, round_key)
    print("Test Case 3 - Computed state:", state)
    assert state == expected_state, "Test Case 3 failed."


def test_add_round_key_state_all_zeros():
    # Test Case 4: All zeros (should return the same state)
    state = [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
    ]

    round_key = [
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        [9, 10, 11, 12],
        [13, 14, 15, 16],
    ]

    expected_state = round_key.copy()  # Should match the round key

    # Perform the AddRoundKey operation for Test Case 4
    add_round_key(state, round_key)
    print("Test Case 4 - Computed state:", state)
    assert state == expected_state, "Test Case 4 failed."
