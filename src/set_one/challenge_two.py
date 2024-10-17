from utils.helper_functions import (
    convert_hex_string_to_bytes,
    xor_two_byte_values,
    convert_to_hex,
)


HEXADECIMAL_STRING_ONE = "1c0111001f010100061a024b53535009181c"
HEXADECIMAL_STRING_TWO = "686974207468652062756c6c277320657965"


def fixed_xor(hex_str1, hex_str2):
    bytes1 = convert_hex_string_to_bytes(hex_str1)
    bytes2 = convert_hex_string_to_bytes(hex_str2)
    xor_result = xor_two_byte_values(bytes1, bytes2)
    return convert_to_hex(xor_result)


if __name__ == "__main__":
    xor_result_in_hex = fixed_xor(HEXADECIMAL_STRING_ONE, HEXADECIMAL_STRING_TWO)
    print("XOR result in hex:", xor_result_in_hex)
