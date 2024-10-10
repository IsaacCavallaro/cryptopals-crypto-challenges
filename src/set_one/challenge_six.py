import base64

ENCRYPTED_FILE = "./src/set_one/challenge_six_codes.txt"
KEYSIZE = range(2, 41)
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


def normalize_hamming_distance(distance, size):
    return distance / size


def convert_string_to_bytes(string):
    """Convert a string into a bytes object using UTF-8 encoding."""
    return string.encode(encoding="utf-8")


def hamming_distance(a, b):
    """Count differing bits between two byte sequences."""
    if len(a) != len(b):
        raise ValueError("Byte sequences must be of the same length.")
    return sum(bin(byte1 ^ byte2).count("1") for byte1, byte2 in zip(a, b))


def transpose_blocks(initial_blocks, key_size):
    transposed = [[] for _ in range(key_size)]
    for block in initial_blocks:
        for i in range(min(len(block), key_size)):
            transposed[i].append(block[i])
    return [bytes(column) for column in transposed]


def convert_txt_file_to_string():
    with open(ENCRYPTED_FILE, "r") as file:
        return file.read().strip()


def find_smallest_hamming_distance(normalized_list):
    return min(normalized_list, key=lambda x: x["normalized_result"])


def chuck_encrypted_bytes(bytes, distance):
    return [bytes[i : i + distance] for i in range(0, len(bytes), distance)]


def xor_each_byte_against_key(key, raw_bytes):
    """XOR each byte of raw_bytes with the given key."""
    return bytes([b ^ key for b in raw_bytes])


def split_transposed_blocks_into_key_chunks(transposed_blocks, key_size):
    chunks = [[] for _ in range(key_size)]
    for i, block in enumerate(transposed_blocks):
        chunks[i % key_size].append(block)
    return chunks


def convert_base64_to_bytes(base64_str):
    """Converts a Base64 encoded string into raw bytes."""
    return base64.b64decode(base64_str)


def score_message(message):
    """Score the message based on the presence of letters and common words."""
    score = 0
    words = message.lower().split()
    letter_score = sum(1 for char in message.lower() if char in LETTERS)
    word_score = sum(1 for word in words if word in COMMON_ENGLISH_WORDS)
    return letter_score + (word_score * 2)  # Weight common words more heavily


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


def decrypt_with_repeating_key(raw_bytes, key):
    decrypted_bytes = bytearray(len(raw_bytes))
    key_length = len(key)

    for i in range(len(raw_bytes)):
        key_byte = key[i % key_length]
        decrypted_bytes[i] = raw_bytes[i] ^ key_byte

    return bytes(decrypted_bytes)


def break_repeating_key_xor():
    encrypted_str = convert_txt_file_to_string()
    raw_bytes = convert_base64_to_bytes(encrypted_str)
    all_keys_normalised = []

    for key in KEYSIZE:
        chunk = raw_bytes[: key * 2]
        byte_a = chunk[:key]
        byte_b = chunk[key:]
        distance = hamming_distance(byte_a, byte_b)
        normalized_result = normalize_hamming_distance(distance, key)
        all_keys_normalised.append({"key": key, "normalized_result": normalized_result})

    smallest_hamming_distance = find_smallest_hamming_distance(all_keys_normalised)
    initial_blocks = chuck_encrypted_bytes(raw_bytes, smallest_hamming_distance["key"])

    transposed_blocks = transpose_blocks(
        initial_blocks, smallest_hamming_distance["key"]
    )
    transposed_block_chunks = split_transposed_blocks_into_key_chunks(
        transposed_blocks, smallest_hamming_distance["key"]
    )

    final_key = []
    for chunk in transposed_block_chunks:
        best_score = 0
        best_key = None
        best_message = None

        for block in chunk:
            for potential_key in range(256):
                score, decrypted_message = decrypt_message_with_key_and_score(
                    potential_key, block
                )
                best_score, best_key, best_message = update_best_key_if_needed(
                    score,
                    decrypted_message,
                    potential_key,
                    best_score,
                    best_key,
                    best_message,
                )

        final_key.append(best_key)

    final_key_str = "".join(chr(byte) for byte in final_key if byte is not None)
    print(f"The best repeating XOR key is: {final_key_str}")

    # Decrypt the message
    key = final_key_str.encode()
    decrypted_message = decrypt_with_repeating_key(raw_bytes, key)

    # Decode the decrypted bytes to a string for readability
    decoded_message = decrypted_message.decode("utf-8", errors="ignore")
    print("Decrypted message:", decoded_message)


if __name__ == "__main__":
    break_repeating_key_xor()
