from set_one.add_round_key import (
    is_equal_to_16_bytes,
)


def test_is_equal_to_16_bytes():
    assert is_equal_to_16_bytes(b"1234567890123456")  # Exactly 16 bytes
    assert is_equal_to_16_bytes(b"YELLOW SUBMARINE")
    assert not is_equal_to_16_bytes(b"123456789012345")  # 15 bytes
    assert not is_equal_to_16_bytes(b"12345678901234567")  # 17 bytes
    assert not is_equal_to_16_bytes(b"")  # 0 bytes
    assert not is_equal_to_16_bytes(b"1234567890")  # 10 bytes
