ENCRYPTED_FILE = "./src/set_one/challenge_six_codes.txt"
KEYSIZE = range(2, 41)


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


def transpose_blocks():
    pass


def convert_txt_file_to_string():
    with open(ENCRYPTED_FILE, "r") as file:
        return file.read()


# if smallest distance !0 and smaller than latest distance then input distance
# We update the smallest distance


def break_repeating_key_xor():
    encrypted_str = convert_txt_file_to_string()
    for key in KEYSIZE:
        smallest_distance = 0
        # Retrieve the first chunk of bytes with a length of key * 2
        chunk = encrypted_str[: key * 2]

        # Split the chunk into two equal parts
        byte_a = chunk[:key]
        byte_b = chunk[key:]

        distance = hamming_distance(byte_a, byte_b)
        normilized_result = normilize_hamming_distance(distance, key)


if __name__ == "__main__":
    break_repeating_key_xor()

    # FOR INITIAL TESTING PURPOSES ONLY
    # TEST_STRING_ONE = "this is a test"
    # TEST_STRING_TWO = "wokka wokka!!!"
    # bytes_one = convert_string_to_bytes(TEST_STRING_ONE)
    # bytes_two = convert_string_to_bytes(TEST_STRING_TWO)
    # print(hamming_distance(bytes_one, bytes_two))
