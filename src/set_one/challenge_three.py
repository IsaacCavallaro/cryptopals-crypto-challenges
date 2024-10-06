def single_byte_xor_cipher():
    hex_str = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    raw_bytes = bytes.fromhex(hex_str)

    letters = [
        'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p',
        'q', 'r', 's', 't',
        'u', 'v', 'w', 'x',
        'y', 'z',
    ]

    def score_message(message):
        """Score the message based on the presence of letters."""
        score = 0
        for char in message.lower():
            if char in letters:
                score += 1 
        return score

    best_score = 0
    best_decrypted_message = ""
    best_key = 0

    # Iterate over all possible single-byte keys (0 to 255)
    for key in range(256):
        # XOR each byte of raw_bytes with the current key
        decrypted_bytes = bytes([b ^ key for b in raw_bytes])
        # Decode the bytes to a string
        decrypted_message = decrypted_bytes.decode(errors='ignore')  # Ignore errors for non-printable characters
        
        # Score the decrypted message
        current_score = score_message(decrypted_message)

        # Check if this score is better than the best score found so far
        if current_score > best_score:
            best_score = current_score
            best_decrypted_message = decrypted_message
            best_key = key

    # Print the best result
    print(f"Best Key: {best_key} ('{chr(best_key)}') -> Decrypted: {best_decrypted_message} with score: {best_score}")

if __name__ == "__main__":
    single_byte_xor_cipher()
