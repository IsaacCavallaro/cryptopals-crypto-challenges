from utils.helper_functions import (
    convert_txt_file_to_string,
    decrypt_message_with_key_and_score,
    update_best_key_if_needed,
    normalize_hamming_distance,
    hamming_distance,
    transpose_blocks,
    find_smallest_hamming_distance,
    chuck_encrypted_bytes,
    split_transposed_blocks_into_key_chunks,
    convert_base64_to_bytes,
    decrypt_message_with_key_and_score,
    update_best_key_if_needed,
    decrypt_with_repeating_key,
    divide_ciphertext_into_keysized_chunks,
    convert_bytes_sequence_to_string,
)

ENCRYPTED_FILE = "./src/set_one/challenge_six_codes.txt"
KEYSIZE = range(2, 41)


def break_repeating_key_xor(raw_bytes: bytes):
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
