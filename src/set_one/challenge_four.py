HEXADECIMALS_FILE = "./src/set_one/challenge_four_codes.txt"
LETTERS = set("abcdefghijklmnopqrstuvwxyz")

# fmt: off
COMMON_ENGLISH_WORDS = set(
    [
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "it", "I", "you", 
        "he", "she", "we", "they", "at", "this", "but", "not", "are", "from", "by",
        "as", "or", "an", "if", "would", "all", "my", "one", "their", "what", "so",
        "up", "out", "about", "who", "get", "which", "go", "me", "when", "make",
        "can", "like", "time", "no", "just", "him", "know", "take", "people", "into",
        "year", "your", "good", "some", "could", "them", "see", "other", "than",
        "then", "now", "look", "only", "come", "its", "over", "think", "also",
        "back", "after", "use", "two", "how", "our", "work", "first", "well", "way",
        "even", "new", "want", "because", "any", "these", "give", "day", "most", "us"
    ]
)
# fmt: on


def convert_hex_string_to_bytes(str):
    return bytes.fromhex(str)


def xor_each_byte_against_key(key, raw_bytes):
    """XOR each byte of raw_bytes with the given key."""
    return bytes([b ^ key for b in raw_bytes])


def decode_bytes_to_string(byte_data):
    """Decode bytes to string, ignoring non-printable characters."""
    return byte_data.decode(errors="ignore")


def decrypt_message_with_key_and_score(key, raw_bytes):
    """Decrypt the bytes message with the given key and scores it."""
    decrypted_bytes = xor_each_byte_against_key(key, raw_bytes)
    decrypted_message = decode_bytes_to_string(decrypted_bytes)
    score = score_message(decrypted_message)
    return score, decrypted_message


def convert_file_to_list():
    with open(HEXADECIMALS_FILE, "r") as file:
        return file.read().splitlines()


def score_message(message):
    """Score the message based on the presence of letters and common words."""
    score = 0
    words = message.lower().split()

    # Score based on letter presence
    letter_score = sum(1 for char in message.lower() if char in LETTERS)

    # Score based on common words presence
    word_score = sum(1 for word in words if word in COMMON_ENGLISH_WORDS)

    # Combine scores (you can adjust the weight of each component)
    return letter_score + (word_score * 2)  # Weight common words more heavily


def update_best_key_if_needed(
    current_score, decrypted_message, key, best_score, best_key, best_message
):
    """Update the best key, message, and score if the current score is better."""
    if current_score > best_score:
        return current_score, key, decrypted_message
    return best_score, best_key, best_message


def find_message_with_best_score(decrypted_list):
    return max(decrypted_list, key=lambda x: x["score"])


def detect_single_character_xor():
    hex_lines_list = convert_file_to_list()
    best_decrypted_list = []  # List to store best decrypted messages

    # Process each hex string in the list
    for hex_str in hex_lines_list:
        raw_bytes = convert_hex_string_to_bytes(hex_str)

        best_score = 0
        best_decrypted_message = ""
        best_key = 0

        # Iterate over all possible single-byte keys (0 to 255)
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

        # Store the best result for the current hex string in the list
        best_decrypted_list.append(
            {
                "hex": hex_str,
                "best_key": best_key,
                "decrypted_message": best_decrypted_message,
                "score": best_score,
            }
        )

    return find_message_with_best_score(best_decrypted_list)


if __name__ == "__main__":
    best_overall = detect_single_character_xor()
    print(
        "Best Overall:\n"
        "Hex: {}\n"
        "Best Key: {} ('{}') -> Decrypted: {} with score: {}\n".format(
            best_overall["hex"],
            best_overall["best_key"],
            chr(best_overall["best_key"]),
            best_overall["decrypted_message"],
            best_overall["score"],
        )
    )
