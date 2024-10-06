def fixed_xor():
    hex_str1 = '1c0111001f010100061a024b53535009181c'
    hex_str2 = '686974207468652062756c6c277320657965'

    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)

    # XOR the two byte sequences
    result = bytes(a ^ b for a, b in zip(bytes1, bytes2))

    print("XOR result in hex:", result.hex())

if __name__ == "__main__":
    fixed_xor()