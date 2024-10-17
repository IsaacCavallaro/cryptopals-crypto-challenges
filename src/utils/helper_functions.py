import base64
from base64 import b64encode

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


# Convert functions
def convert_file_to_list(hex_file):
    with open(hex_file, "r") as file:
        return file.read().splitlines()


def convert_txt_file_to_string(encrypted_file):
    with open(encrypted_file, "r") as file:
        return file.read()


def convert_bytes_to_hex(byte_array):
    """Convert a byte array to a hexadecimal string representation."""
    return byte_array.hex()


def convert_hex_string_to_bytes(str):
    return bytes.fromhex(str)


def convert_string_to_bytes(string):
    """Convert a string into a bytes object using UTF-8 encoding."""
    return string.encode(encoding="utf-8")


def convert_raw_bytes_to_base_64(bytes):
    return b64encode(bytes)


def convert_to_hex(xor_result):
    return xor_result.hex()


def convert_base64_to_bytes(base64_str):
    """Converts a Base64 encoded string into raw bytes."""
    return base64.b64decode(base64_str)


def decode_base64_bytes(base_64_bytes):
    return base_64_bytes.decode()


def decode_bytes_to_string(byte_data):
    """Decode bytes to string, ignoring non-printable characters."""
    return byte_data.decode(errors="ignore")


def convert_bytes_sequence_to_string(byte_sequence):
    """
    Convert a sequence of bytes into a string, ignoring any None values.
    """
    return "".join(chr(byte) for byte in byte_sequence if byte is not None)


# Xor functions
def xor_byte_with_key(byte, key_byte):
    """Perform XOR operation between a single byte and a key byte."""
    return byte ^ key_byte


def xor_two_byte_values(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))


def xor_each_byte_against_key(key, raw_bytes):
    """XOR each byte of raw_bytes with the given key."""
    return bytes([b ^ key for b in raw_bytes])


# Calcuation functions
def normalize_hamming_distance(distance, size):
    return distance / size


def find_message_with_best_score(decrypted_list):
    return max(decrypted_list, key=lambda x: x["score"])


def find_smallest_hamming_distance(distances):
    # Sort the list of key distances by normalized_result
    distances = sorted(distances, key=lambda x: x["normalized_result"])
    return distances[0]


def hamming_distance(a, b):
    """Count differing bits between two byte sequences."""
    if len(a) != len(b):
        raise ValueError("Byte sequences must be of the same length.")
    return sum(bin(byte1 ^ byte2).count("1") for byte1, byte2 in zip(a, b))


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


# Block functions
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


def chuck_encrypted_bytes(bytes, distance):
    """Breaks the bytes input into chunks equal to the given distance"""
    return [bytes[i : i + distance] for i in range(0, len(bytes), distance)]


def divide_ciphertext_into_keysized_chunks(key_size, raw_bytes):
    """
    Returns the total number of chunks that can be created with the guessed key size.
    """
    return len(raw_bytes) // key_size


# Decrypt functions
def decrypt_message_with_key_and_score(key, raw_bytes):
    """Decrypt the bytes message with the given key and scores it."""
    decrypted_bytes = xor_each_byte_against_key(key, raw_bytes)
    decrypted_message = decode_bytes_to_string(decrypted_bytes)
    score = score_message(decrypted_message)
    return score, decrypted_message


def decrypt_with_repeating_key(raw_bytes, key):
    decrypted_bytes = bytearray(len(raw_bytes))
    key_length = len(key)

    for i in range(len(raw_bytes)):
        key_byte = key[i % key_length]
        decrypted_bytes[i] = raw_bytes[i] ^ key_byte

    return bytes(decrypted_bytes)
