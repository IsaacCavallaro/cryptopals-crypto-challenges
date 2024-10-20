import pytest
from set_one.shift_rows import shift_rows


# AES ENCRYPTION SHIFT ROWS TESTS
def test_valid_shift_rows():
    example_state = [
        [0, 1, 2, 3],
        [4, 5, 6, 7],
        [8, 9, 10, 11],
        [12, 13, 14, 15],
    ]

    expected_result = [
        [0, 1, 2, 3],  # No shift for the first row
        [5, 6, 7, 4],  # Shift the second row to the left by 1
        [10, 11, 8, 9],  # Shift the third row to the left by by 2
        [15, 12, 13, 14],  # Shift the fourth row to the left by by 3
    ]

    assert (
        shift_rows(
            example_state,
        )
        == expected_result
    )


def test_valid_shift_rows_with_letters():
    example_state = [
        ["a", "b", "c", "d"],
        ["e", "f", "g", "h"],
        ["i", "j", "k", "l"],
        ["m", "n", "o", "p"],
    ]

    expected_result = [
        ["a", "b", "c", "d"],  # No shift for the first row
        ["f", "g", "h", "e"],  # Shift the second row to the left by 1
        ["k", "l", "i", "j"],  # Shift the third row to the left by by 2
        ["p", "m", "n", "o"],  # Shift the fourth row to the left by by 3
    ]

    assert (
        shift_rows(
            example_state,
        )
        == expected_result
    )


def test_invalid_shift_rows():
    invalid_state_matrix = [
        [0, 1, 2, 3],
    ]
    with pytest.raises(ValueError, match="Input must be a 4 by 4 matrix"):
        shift_rows(invalid_state_matrix)
