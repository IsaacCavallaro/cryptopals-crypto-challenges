from utils.lookup_tables import SBOX, SBOXINV


def demonstrate_sbox_and_inverse(byte: int) -> None:
    """
    This function demonstrates the substitution using the S-box and then
    the recovery of the original byte using the inverse S-box.

    Parameters:
    byte (int): The byte value to be substituted and then recovered.
    """
    # Substitute the byte using the S-box
    substituted_byte = SBOX[byte]

    # Use the inverse S-box to recover the original byte
    recovered_byte = SBOXINV[substituted_byte]

    return byte, substituted_byte, recovered_byte


if __name__ == "__main__":
    byte, substituted_byte, recovered_byte = demonstrate_sbox_and_inverse(0x53)

    print(
        f"Original byte: {hex(byte)}, "
        f"Substituted byte: {hex(substituted_byte)}, "
        f"Recovered byte: {hex(recovered_byte)}"
    )
