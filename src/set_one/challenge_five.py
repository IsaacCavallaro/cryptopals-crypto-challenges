from utils.helper_functions import (
    convert_string_to_bytes,
    xor_byte_with_key,
    convert_bytes_to_hex,
)

STANZA = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"

KEY = "ICE"


def repeating_key_xor(stanza_bytes: bytes, key_bytes: bytes) -> str:
    """Perform repeating-key XOR encryption on the given bytes using the key."""
    result_bytes = bytearray()

    # Loop over each byte in the stanza and apply XOR with the corresponding key byte
    for i, byte in enumerate(stanza_bytes):
        key_byte = key_bytes[i % len(key_bytes)]
        result_bytes.append(xor_byte_with_key(byte, key_byte))

    return convert_bytes_to_hex(result_bytes)


if __name__ == "__main__":
    stanza_bytes = convert_string_to_bytes(STANZA)
    key_bytes = convert_string_to_bytes(KEY)
    encrypted_hex = repeating_key_xor(stanza_bytes, key_bytes)
    print(encrypted_hex)
