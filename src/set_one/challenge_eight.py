from utils.helper_functions import (
    convert_string_to_bytes,
    chunk_bytes_into_blocks,
    read_file_to_lines,
)

ENCRYPTED_FILE = "./src/set_one/challenge_eight_codes.txt"


def detect_aes_in_ecb_mode(raw_bytes):
    blocks = chunk_bytes_into_blocks(raw_bytes, 16)
    unique_blocks = set(blocks)
    return len(unique_blocks) < len(blocks)


if __name__ == "__main__":
    lines = read_file_to_lines(ENCRYPTED_FILE)

    for i, hex_encoded_cipher_text in enumerate(lines):
        # Convert each hex-encoded line to raw bytes
        raw_bytes = convert_string_to_bytes(hex_encoded_cipher_text.strip())

        # Check for repeated blocks in each line
        if detect_aes_in_ecb_mode(raw_bytes):
            print(f"Line {i + 1} is likely encrypted in ECB mode.")
        else:
            print(f"Line {i + 1} shows no ECB mode signs.")
