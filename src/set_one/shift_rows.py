from utils.helper_functions import is_valid_state_matrix


def shift_rows(state: list[list[int]]) -> list[list[int]]:
    """
    Perform the AES Shift Rows transformation on a 4x4 state matrix.
    """
    if is_valid_state_matrix(state):
        # Perform the row shifts
        shifted_state = [
            state[0],  # No shift for the first row
            state[1][1:] + state[1][:1],  # Shift the second row to the left by 1
            state[2][2:] + state[2][:2],  # Shift the third row to the left by by 2
            state[3][3:] + state[3][:3],  # Shift the fourth row to the left by by 3
        ]

        return shifted_state
    raise ValueError("Input must be a 4 by 4 matrix")


# Example usage
example_state = [
    [0x00, 0x01, 0x02, 0x03],
    [0x10, 0x11, 0x12, 0x13],
    [0x20, 0x21, 0x22, 0x23],
    [0x30, 0x31, 0x32, 0x33],
]

if __name__ == "__main__":
    shifted_state = shift_rows(example_state)
    print(shifted_state)
    for row in shifted_state:
        print([hex(byte) for byte in row])
