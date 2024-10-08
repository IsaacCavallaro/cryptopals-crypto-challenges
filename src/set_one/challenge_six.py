TEST_STRING_ONE = "this is a test"
TEST_STRING_TWO = "wokka wokka!!!"


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


if __name__ == "__main__":
    bytes_one = convert_string_to_bytes(TEST_STRING_ONE)
    bytes_two = convert_string_to_bytes(TEST_STRING_TWO)
    print(hamming_distance(bytes_one, bytes_two))
