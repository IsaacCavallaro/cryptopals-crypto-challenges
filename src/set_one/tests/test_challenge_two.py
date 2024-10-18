import pytest
from set_one.challenge_two import fixed_xor


def test_valid_fixed_xor():
    # Test case with valid hexadecimal strings
    assert (
        fixed_xor(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
        )
        == "746865206b696420646f6e277420706c6179"
    )
