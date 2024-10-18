from typing import List

# Padding with spaces to make it 16 bytes
TEXT_TO_ENCRYPT = b"This is some p" + b" " * 2
KEY = b"YELLOW SUBMARINE"  # 16 bytes


def is_equal_to_16_bytes(data):
    """Check if the input data is exactly 16 bytes long."""
    return len(data) == 16


def add_round_key(state, round_key):
    """Perform the AddRoundKey operation."""
    for i in range(4):  # For each row
        for j in range(4):  # For each column
            state[i][j] ^= round_key[i][j]  # XOR the state with the round key


def format_state(state):
    """Helper function to format the state matrix for output."""
    return [["{:02x}".format(x) for x in row] for row in state]


def bytes_to_state(bytes_input: bytes) -> List[List[int]]:
    """Convert a 16-byte input to a 4x4 state matrix."""
    if not isinstance(bytes_input, bytes):
        raise ValueError("Input must be of type 'bytes'.")

    if not is_equal_to_16_bytes(bytes_input):
        raise ValueError("Input must be exactly 16 bytes long.")

    return [list(bytes_input[i : i + 4]) for i in range(0, 16, 4)]


def example_add_round_key(plaintext, key):
    state = bytes_to_state(plaintext)
    round_key = bytes_to_state(key)

    initial_state = format_state(state)
    round_key_formatted = format_state(round_key)

    # Perform AddRoundKey operation
    add_round_key(state, round_key)

    final_state = format_state(state)

    return initial_state, round_key_formatted, final_state


if __name__ == "__main__":
    initial, round_key, final = example_add_round_key(TEXT_TO_ENCRYPT, KEY)
    print("Initial State:")
    print(initial)
    print("\nRound Key:")
    print(round_key)
    print("\nState after AddRoundKey:")
    print(final)
