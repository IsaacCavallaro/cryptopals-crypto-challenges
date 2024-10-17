import pytest
from set_one.hamming_distance import hamming_distance, convert_string_to_bytes


def test_invalid_inputs():
    with pytest.raises(ValueError, match="Both inputs must be of type 'bytes'."):
        hamming_distance(
            "this is a test",
            "",
        )


def test_valid_hamming_distance():
    assert (
        hamming_distance(
            convert_string_to_bytes("this is a test"),
            convert_string_to_bytes("wokka wokka!!!"),
        )
        == 37
    )


def test_incorrect_length():
    with pytest.raises(ValueError, match="Byte sequences must be of the same length."):
        hamming_distance(
            convert_string_to_bytes("this is a test"),
            convert_string_to_bytes(""),
        )
