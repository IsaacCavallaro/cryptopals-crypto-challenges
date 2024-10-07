HEXADECIMAL_STRING = (
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)

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


def score_message(message):
    """Score the message based on the presence of letters."""
    score = 0
    for char in message.lower():
        if char in LETTERS:
            score += 1
    return score


def convert_hex_string_to_bytes(hex_str):
    return bytes.fromhex(hex_str)


def xor_each_byte_against_key(key, raw_bytes):
    """XOR each byte of raw_bytes with the given key."""
    return bytes([b ^ key for b in raw_bytes])


def decode_bytes_to_string(byte_data):
    """Decode bytes to string, ignoring non-printable characters."""
    return byte_data.decode(errors="ignore")


def evaluate_key(key, raw_bytes):
    """Decrypt the message with the given key and score it."""
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


def find_best_single_byte_key(raw_bytes):
    """Find the best single-byte XOR key that produces the highest-scoring message."""
    best_score = 0
    best_decrypted_message = ""
    best_key = 0

    # Iterate over all possible single-byte keys (0 to 255)
    # We use 256 here because a byte can have 256 possible values (8 bits: 0-255)
    for key in range(256):
        current_score, decrypted_message = evaluate_key(key, raw_bytes)
        best_score, best_key, best_decrypted_message = update_best_key_if_needed(
            current_score,
            decrypted_message,
            key,
            best_score,
            best_key,
            best_decrypted_message,
        )

    return best_key, best_decrypted_message, best_score


def single_byte_xor_cipher(hex_str):
    """Decrypt a hexadecimal string using the best single-byte XOR key."""
    raw_bytes = convert_hex_string_to_bytes(hex_str)
    return find_best_single_byte_key(raw_bytes)


if __name__ == "__main__":
    best_key, best_decrypted_message, best_score = single_byte_xor_cipher(
        HEXADECIMAL_STRING
    )
    print(
        f"Best Key: {best_key} ('{chr(best_key)}') -> Decrypted: {best_decrypted_message} with score: {best_score}"
    )
