import pytest
import base64
from utils.helper_functions import (
    HexadecimalError,
    convert_file_to_list,
    convert_file_to_string,
    convert_bytes_to_hex,
    convert_hex_string_to_bytes,
    convert_string_to_bytes,
    convert_raw_bytes_to_base_64,
    decode_base64_bytes,
    convert_bytes_sequence_to_string,
    xor_byte_with_key,
    str_is_hexadecimal,
)


# Validate data functions
def test_str_is_hexadecimal():
    assert str_is_hexadecimal("1") == True
    assert str_is_hexadecimal("9") == True
    assert str_is_hexadecimal("a") == True
    assert str_is_hexadecimal("A") == True
    assert str_is_hexadecimal("fF") == True
    with pytest.raises(HexadecimalError):
        str_is_hexadecimal("g")


# Convert functions
def test_valid_convert_file_to_list(tmp_path):
    # Create a temporary file with some hex data
    test_file = tmp_path / "test_hex.txt"
    content = "1a2b3c\n4d5e6f\n7g8h9i"
    test_file.write_text(content)
    assert convert_file_to_list(str(test_file)) == ["1a2b3c", "4d5e6f", "7g8h9i"]
    assert isinstance(convert_file_to_list(str(test_file)), list)


def test_invalid_convert_file_to_list(tmp_path):
    with pytest.raises(FileNotFoundError):
        convert_file_to_list("non_existent_file.txt")


def test_valid_convert_file_to_string(tmp_path):
    test_file = tmp_path / "test_file.txt"
    content = "Hello there"
    test_file.write_text(content)
    assert convert_file_to_string(test_file) == "Hello there"


def test_valid_convert_bytes_to_hex():
    assert convert_bytes_to_hex(b"\x00\x01\x02\x03\x0f\x10\xff") == "000102030f10ff"


def test_invalid_convert_bytes_to_hex():
    with pytest.raises(ValueError, match="Input must be of type 'bytes'."):
        convert_bytes_to_hex("a")

    with pytest.raises(ValueError, match="Input must be of type 'bytes'."):
        convert_bytes_to_hex(1)


def test_valid_convert_hex_string_to_bytes():
    assert (
        convert_hex_string_to_bytes("000102030f10ff") == b"\x00\x01\x02\x03\x0f\x10\xff"
    )
    assert isinstance(convert_hex_string_to_bytes("000102030f10ff"), bytes)


def test_valid_convert_string_to_bytes():
    assert convert_string_to_bytes("Hello, World!") == b"Hello, World!"
    assert (
        convert_string_to_bytes("Café") == b"Caf\xc3\xa9"
    )  # UTF-8 encoding for "Café"
    assert convert_string_to_bytes("") == b""
    assert convert_string_to_bytes("Hello 🌍") == b"Hello \xf0\x9f\x8c\x8d"
    assert convert_string_to_bytes("123456") == b"123456"


def test_valid_convert_raw_bytes_to_base_64():
    assert convert_raw_bytes_to_base_64(b"Hello, World!") == b"SGVsbG8sIFdvcmxkIQ=="


def test_valid_decode_base64_bytes():
    assert decode_base64_bytes(b"SGVsbG8sIFdvcmxkIQ==") == "SGVsbG8sIFdvcmxkIQ=="
    assert isinstance(
        decode_base64_bytes(b"SGVsbG8sIFdvcmxkIQ=="), str
    ), "Output should be of type str"


def test_valid_convert_bytes_sequence_to_string():
    byte_sequence = [
        84,
        101,
        114,
        109,
        105,
        110,
        97,
        116,
        111,
        114,
        32,
        88,
        58,
        32,
        66,
        114,
        105,
        110,
        103,
        32,
        116,
        104,
        101,
        32,
        110,
        111,
        105,
        115,
        101,
    ]
    assert (
        convert_bytes_sequence_to_string(byte_sequence)
        == "Terminator X: Bring the noise"
    )

    assert isinstance(
        convert_bytes_sequence_to_string(byte_sequence), str
    ), "Output should be of type str"


# Xor functions
def test_valid_xor_byte_with_key():
    assert xor_byte_with_key(0b11111111, 0b00000000) == 0b11111111  # 255 ^ 0
    assert xor_byte_with_key(0b00000000, 0b11111111) == 0b11111111  # 0 ^ 255
    assert xor_byte_with_key(0b11110000, 0b10101010) == 0b01011010  # 240 ^ 170

    # Test boundary conditions
    assert xor_byte_with_key(0, 255) == 255
    assert xor_byte_with_key(255, 0) == 255
    assert xor_byte_with_key(0, 0) == 0
    assert xor_byte_with_key(255, 255) == 0


def test_in_valid_xor_byte_with_key():
    with pytest.raises(TypeError):
        xor_byte_with_key("a", 1)  # string should raise TypeError
    with pytest.raises(TypeError):
        xor_byte_with_key(1, None)  # None should raise TypeError
