import base64

ENCRYPTED_FILE = "./src/set_one/challenge_six_codes.txt"
KEYSIZE = range(2, 41)
LETTERS = set("abcdefghijklmnopqrstuvwxyz ")  # Need to include space

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
    """
    Transpose the given blocks of bytes into blocks of key size.

    This function takes blocks of bytes and rearranges them so that each new block
    contains all bytes at the same position in the original blocks. This is useful
    when solving a repeating-key XOR because each block can then be treated as if
    it was encrypted using a single-byte XOR cipher.
    """
    transposed = [[] for _ in range(key_size)]
    for block in initial_blocks:
        for i in range(min(len(block), key_size)):
            transposed[i].append(block[i])
    return [bytes(column) for column in transposed]


def convert_txt_file_to_string(encrypted_file):
    with open(encrypted_file, "r") as file:
        return file.read()


def find_smallest_hamming_distance(distances):
    # Sort the list of key distances by normalized_result
    distances = sorted(distances, key=lambda x: x["normalized_result"])
    return distances[0]


def chuck_encrypted_bytes(bytes, distance):
    """Breaks the bytes input into chunks equal to the given distance"""
    return [bytes[i : i + distance] for i in range(0, len(bytes), distance)]


def xor_each_byte_against_key(key, raw_bytes):
    """XOR each byte of raw_bytes with the given key."""
    return bytes([b ^ key for b in raw_bytes])


def split_transposed_blocks_into_key_chunks(transposed_blocks, key_size):
    """
    Takes transposed blocks and splits them into chunks where each
    chunk corresponds to a specific key byte. Allowing for analysis of each
    key byte separately when solving the repeating-key XOR.
    """
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


def divide_ciphertext_into_keysized_chunks(key_size, raw_bytes):
    """
    Returns the total number of chunks that can be created with the guessed key size.
    """
    return len(raw_bytes) // key_size


def convert_bytes_sequence_to_string(byte_sequence):
    """
    Convert a sequence of bytes into a string, ignoring any None values.
    """
    return "".join(chr(byte) for byte in byte_sequence if byte is not None)


def break_repeating_key_xor(raw_bytes):
    all_keys_normalised = []

    for key in KEYSIZE:
        distances = []

        total_chunks = divide_ciphertext_into_keysized_chunks(key, raw_bytes)
        for i in range(total_chunks - 1):
            chunk_a = raw_bytes[i * key : (i + 1) * key]
            chunk_b = raw_bytes[(i + 1) * key : (i + 2) * key]
            distance = hamming_distance(chunk_a, chunk_b)
            distances.append(distance)

        # Calculate the average normalized Hamming distance for the current KEYSIZE
        if distances:
            average_distance = sum(distances) / len(distances)
            normalized_result = normalize_hamming_distance(average_distance, key)
            all_keys_normalised.append(
                {"key": key, "normalized_result": normalized_result}
            )

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

    final_key_str = convert_bytes_sequence_to_string(final_key)
    print(f"The best repeating XOR key is: {final_key_str}")

    # Decrypt the message
    key = final_key_str.encode()
    decrypted_message = decrypt_with_repeating_key(raw_bytes, key)
    return decrypted_message.decode("utf-8", errors="ignore")


if __name__ == "__main__":
    encrypted_str = convert_txt_file_to_string(ENCRYPTED_FILE)
    raw_bytes = convert_base64_to_bytes(encrypted_str)
    decoded_message = break_repeating_key_xor(raw_bytes)
    print("Decrypted message:", decoded_message)
