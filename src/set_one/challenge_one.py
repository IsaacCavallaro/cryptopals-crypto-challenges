from utils.helper_functions import (
    convert_hex_string_to_bytes,
    convert_raw_bytes_to_base_64,
    decode_base64_bytes,
)

HEXADECIMAL_STRING = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"


def hex_to_base64(hex_str: str) -> str:
    raw_bytes: bytes = convert_hex_string_to_bytes(hex_str)
    b64_bytes: bytes = convert_raw_bytes_to_base_64(raw_bytes)
    return decode_base64_bytes(b64_bytes)


if __name__ == "__main__":
    decoded_b64_bytes: str = hex_to_base64(HEXADECIMAL_STRING)
    print("hex in base64:", decoded_b64_bytes)
