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


def normilize_hamming_distance(distance, size):
    return distance / size


def convert_string_to_bytes(string):
    """Convert a string into a bytes object using UTF-8 encoding."""
    return string.encode(encoding="utf-8")


def hamming_distance(a, b):
    """For each pair of bytes, count how many bits differ
    Add up all those counts to get the total number of differing bits between the two sequences.
    """
    # Ensure the two byte sequences are of the same length
    if len(a) != len(b):
        raise ValueError("Byte sequences must be of the same length.")

    # Compute the Hamming distance by XORing each pair of bytes and counting the 1s
    return sum(bin(byte1 ^ byte2).count("1") for byte1, byte2 in zip(a, b))


def transpose_blocks(initial_blocks, key_size):
    # Initialize a list of lists to hold transposed bytes
    transposed = [[] for _ in range(key_size)]

    # Iterate over each block and distribute bytes into transposed columns
    for block in initial_blocks:
        for i in range(min(len(block), key_size)):
            transposed[i].append(block[i])

    # Convert each list in transposed into bytes
    return [bytes(column) for column in transposed]


def convert_txt_file_to_string():
    with open(ENCRYPTED_FILE, "r") as file:
        return file.read().strip()


def find_smallest_hamming_distance(normlized_list):
    return min(normlized_list, key=lambda x: x["normilized_result"])


def chuck_encrypted_bytes(bytes, distance):
    return [bytes[i : i + distance] for i in range(0, len(bytes), distance)]


def xor_each_byte_against_key(key, raw_bytes):
    """XOR each byte of raw_bytes with the given key."""
    return bytes([b ^ key for b in raw_bytes])


def split_transposed_blocks_into_key_chunks(transposed_blocks, key_size):
    chunks = [[] for _ in range(key_size)]

    # Distribute the bytes into the respective chunks
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

    # Score based on letter presence
    letter_score = sum(1 for char in message.lower() if char in LETTERS)

    # Score based on common words presence
    word_score = sum(1 for word in words if word in COMMON_ENGLISH_WORDS)

    # Combine scores (you can adjust the weight of each component)
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


def break_repeating_key_xor():
    encrypted_str = convert_txt_file_to_string()
    raw_bytes = convert_base64_to_bytes(encrypted_str)
    all_keys_normalised = []
    for key in KEYSIZE:
        # Retrieve the first chunk of bytes with a length of key * 2
        chunk = raw_bytes[: key * 2]

        # Split the chunk into two equal parts
        byte_a = chunk[:key]
        byte_b = chunk[key:]

        distance = hamming_distance(byte_a, byte_b)
        normilized_result = normilize_hamming_distance(distance, key)

        all_keys_normalised.append(
            {
                "key": key,
                "normilized_result": normilized_result,
            }
        )

    smallest_hamming_distance = find_smallest_hamming_distance(all_keys_normalised)

    initial_blocks = chuck_encrypted_bytes(raw_bytes, smallest_hamming_distance["key"])
    transposed_blocks = transpose_blocks(
        initial_blocks, smallest_hamming_distance["key"]
    )

    transposed_block_chunks = split_transposed_blocks_into_key_chunks(
        transposed_blocks, smallest_hamming_distance["key"]
    )
    print(transposed_block_chunks)

    final_key = []
    for chunk in transposed_block_chunks:
        best_score = 0
        best_key = None
        best_message = None

        # Loop through each block in the current chunk
        for block_index in range(len(chunk)):
            # Try all possible keys for this block (0-255)
            for potential_key in range(256):
                score, decrypted_message = decrypt_message_with_key_and_score(
                    potential_key, chunk[block_index]
                )

                # Update the best key if the current score is higher
                best_score, best_key, best_message = update_best_key_if_needed(
                    score,
                    decrypted_message,
                    potential_key,
                    best_score,
                    best_key,
                    best_message,
                )

        # Append the best key for this chunk to the final repeating-key XOR key
        final_key.append(best_key)

    final_key_str = "".join(chr(byte) for byte in final_key)
    print(f"The best repeating XOR key is: {final_key_str}")


if __name__ == "__main__":
    result = break_repeating_key_xor()
    # print(result)

    # FOR INITIAL TESTING PURPOSES ONLY
    # TEST_STRING_ONE = "this is a test"
    # TEST_STRING_TWO = "wokka wokka!!!"
    # bytes_one = convert_string_to_bytes(TEST_STRING_ONE)
    # bytes_two = convert_string_to_bytes(TEST_STRING_TWO)
    # print(hamming_distance(bytes_one, bytes_two))
