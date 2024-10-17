from base64 import b64encode

# fmt: off
LETTERS = [
    'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p',
    'q', 'r', 's', 't',
    'u', 'v', 'w', 'x',
    'y', 'z',
]
# fmt: on


def convert_hex_string_to_bytes(str):
    return bytes.fromhex(str)


def convert_raw_bytes_to_base_64(bytes):
    return b64encode(bytes)


def decode_base64_bytes(base_64_bytes):
    return base_64_bytes.decode()


def xor_two_byte_values(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))


def convert_to_hex(xor_result):
    return xor_result.hex()


def xor_each_byte_against_key(key, raw_bytes):
    """XOR each byte of raw_bytes with the given key."""
    return bytes([b ^ key for b in raw_bytes])


def score_message(message):
    """Score the message based on the presence of letters."""
    score = 0
    for char in message.lower():
        if char in LETTERS:
            score += 1
    return score


def decode_bytes_to_string(byte_data):
    """Decode bytes to string, ignoring non-printable characters."""
    return byte_data.decode(errors="ignore")


def decrypt_message_with_key_and_score(key, raw_bytes):
    """Decrypt the bytes message with the given key and scores it."""
    decrypted_bytes = xor_each_byte_against_key(key, raw_bytes)
    decrypted_message = decode_bytes_to_string(decrypted_bytes)
    score = score_message(decrypted_message)
    return score, decrypted_message


def update_best_key_if_needed(
    current_score, decrypted_message, key, best_score, best_key, best_message
):
    """Update the best key, message, and score if the current score is better."""
    if current_score > best_score:
        return current_score, key, decrypted_message
    return best_score, best_key, best_message
