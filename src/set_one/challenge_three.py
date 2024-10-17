from utils.helper_functions import (
    convert_hex_string_to_bytes,
    decrypt_message_with_key_and_score,
    update_best_key_if_needed,
)

HEXADECIMAL_STRING = (
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)


def find_best_single_byte_key(raw_bytes):
    """Find the best single-byte XOR key that produces the highest-scoring message."""
    best_score = 0
    best_decrypted_message = ""
    best_key = 0

    # Iterate over all possible single-byte keys (0 to 255)
    # We use 256 here because a byte can have 256 possible values (8 bits: 0-255)
    for key in range(256):
        current_score, decrypted_message = decrypt_message_with_key_and_score(
            key, raw_bytes
        )
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
