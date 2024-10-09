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


def transpose_blocks(initial_blocks, key_size):
    # Create a list to hold the transposed blocks
    transposed = [[] for _ in range(key_size)]

    # Iterate over each block and each byte in the block
    for block in initial_blocks:
        for i in range(len(block)):
            transposed[i].append(block[i])

    # Convert each list in transposed to bytes
    return [bytes(chunk) for chunk in transposed]


def convert_txt_file_to_string():
    with open(ENCRYPTED_FILE, "r") as file:
        return file.read()


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


def break_repeating_key_xor():
    # TODO may need to convert encrypted_str to bytes first
    encrypted_str = convert_txt_file_to_string()
    all_keys_normalised = []
    for key in KEYSIZE:
        # Retrieve the first chunk of bytes with a length of key * 2
        chunk = encrypted_str[: key * 2]

        # Split the chunk into two equal parts
        byte_a = convert_string_to_bytes(chunk[:key])
        byte_b = convert_string_to_bytes(chunk[key:])

        distance = hamming_distance(byte_a, byte_b)
        normilized_result = normilize_hamming_distance(distance, key)

        all_keys_normalised.append(
            {
                "key": key,
                "normilized_result": normilized_result,
            }
        )

    smallest_hamming_distance = find_smallest_hamming_distance(all_keys_normalised)
    encrypted_bytes = convert_string_to_bytes(encrypted_str)
    initial_blocks = chuck_encrypted_bytes(
        encrypted_bytes, smallest_hamming_distance["key"]
    )
    transposed_blocks = transpose_blocks(
        initial_blocks, smallest_hamming_distance["key"]
    )

    transposed_block_chunks = split_transposed_blocks_into_key_chunks(
        transposed_blocks, smallest_hamming_distance["key"]
    )

    print(
        xor_each_byte_against_key(
            smallest_hamming_distance["key"], transposed_block_chunks[0][0]
        )
    )
    print(
        xor_each_byte_against_key(
            smallest_hamming_distance["key"], transposed_block_chunks[1][0]
        )
    )
    print(
        xor_each_byte_against_key(
            smallest_hamming_distance["key"], transposed_block_chunks[2][0]
        )
    )


if __name__ == "__main__":
    result = break_repeating_key_xor()
    # print(result)

    # FOR INITIAL TESTING PURPOSES ONLY
    # TEST_STRING_ONE = "this is a test"
    # TEST_STRING_TWO = "wokka wokka!!!"
    # bytes_one = convert_string_to_bytes(TEST_STRING_ONE)
    # bytes_two = convert_string_to_bytes(TEST_STRING_TWO)
    # print(hamming_distance(bytes_one, bytes_two))
