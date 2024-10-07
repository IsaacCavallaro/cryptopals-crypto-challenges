from base64 import b64encode

HEXADECIMAL_STRING = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"


def convert_hex_string_to_bytes(str):
    return bytes.fromhex(str)


def convert_raw_bytes_to_base_64(bytes):
    return b64encode(bytes)


def decode_base_64_bytes(base_64_bytes):
    return base_64_bytes.decode()


def hex_to_base64(hex_str):
    raw_bytes = convert_hex_string_to_bytes(hex_str)
    b64_bytes = convert_raw_bytes_to_base_64(raw_bytes)
    return decode_base_64_bytes(b64_bytes)


if __name__ == "__main__":
    decoded_b64_bytes = hex_to_base64(HEXADECIMAL_STRING)
    print("hex in base64:", decoded_b64_bytes)
