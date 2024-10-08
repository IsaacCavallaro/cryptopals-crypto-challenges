ENCRYPTED_FILE = "./src/set_one/challenge_six_codes.txt"
KEYSIZE = range(2, 41)
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


def convert_txt_file_to_string():
    with open(ENCRYPTED_FILE, "r") as file:
        return file.read()


def break_repeating_key_xor():
    encrypted_str = convert_txt_file_to_string()
    print(type(encrypted_str))
    for key in KEYSIZE:
        print(key)


if __name__ == "__main__":
    break_repeating_key_xor()

    # FOR INITIAL TESTING PURPOSES ONLY
    # TEST_STRING_ONE = "this is a test"
    # TEST_STRING_TWO = "wokka wokka!!!"
    # bytes_one = convert_string_to_bytes(TEST_STRING_ONE)
    # bytes_two = convert_string_to_bytes(TEST_STRING_TWO)
    # print(hamming_distance(bytes_one, bytes_two))
