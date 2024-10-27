from utils.helper_functions import (
    convert_string_to_bytes,
    read_file_to_lines,
    chunk_bytes_into_blocks,
)

ENCRYPTED_FILE = "./src/set_one/challenge_eight_codes.txt"


def detect_aes_in_ecb_mode(raw_bytes: bytes) -> dict:
    """Check for repeated blocks in the given bytes and return a dictionary of duplicate blocks and their counts."""
    blocks = chunk_bytes_into_blocks(raw_bytes, 16)
    block_counts = {}
    duplicate_blocks = {}

    # Count occurrences of each block
    for block in blocks:
        if block in block_counts:
            block_counts[block] += 1
        else:
            block_counts[block] = 1

    # Collect blocks that appear more than once with their counts
    for block, count in block_counts.items():
        if count > 1:
            duplicate_blocks[block] = count

    return duplicate_blocks


def process_lines(lines: list):
    """Process each line to check for AES encryption in ECB mode and report duplicate blocks and their counts."""
    for i, hex_encoded_cipher_text in enumerate(lines):
        # Convert each hex-encoded line to raw bytes
        raw_bytes = convert_string_to_bytes(hex_encoded_cipher_text.strip())

        duplicate_blocks = detect_aes_in_ecb_mode(raw_bytes)
        if duplicate_blocks:
            print(f"Line {i + 1} is likely encrypted in ECB mode.")
            for block, count in duplicate_blocks.items():
                print(f"Block: {block.hex()} | Count: {count}")
            print(f"Total duplicate blocks: {len(duplicate_blocks)}")
        else:
            print(f"Line {i + 1} shows no ECB mode signs.")


if __name__ == "__main__":
    lines = read_file_to_lines(ENCRYPTED_FILE)
    process_lines(lines)
