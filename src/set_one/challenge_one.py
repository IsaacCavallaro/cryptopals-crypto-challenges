from base64 import b64encode

def hex_to_base64():
    # Hex string to raw bytes, then base64 encode
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    raw_bytes = bytes.fromhex(hex_str)
    b64_bytes = b64encode(raw_bytes)

    # Print the base64-encoded string
    print('hex in base64:', b64_bytes.decode())

if __name__ == "__main__":
    hex_to_base64()

