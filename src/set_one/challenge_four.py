def detect_single_character_xor():
    with open("./src/set_one/challenge_four_codes.txt", "r") as file:
        hex_lines_list = file.read().splitlines()

    letters = set("abcdefghijklmnopqrstuvwxyz")

    # fmt: off
    common_words = set(
        [
            "the", "be", "to", "of", "and", "a", "in", "that", "have", "it", "I", "you", 
            "he", "she", "we", "they", "at", "this", "but", "not", "are", "from", "by",
            "as", "or", "an", "if", "would", "all", "my", "one", "their", "what", "so",
            "up", "out", "about", "who", "get", "which", "go", "me", "when", "make",
            "can", "like", "time", "no", "just", "him", "know", "take", "people", "into",
            "year", "your", "good", "some", "could", "them", "see", "other", "than",
            "then", "now", "look", "only", "come", "its", "over", "think", "also",
            "back", "after", "use", "two", "how", "our", "work", "first", "well", "way",
            "even", "new", "want", "because", "any", "these", "give", "day", "most", "us"
        ]
    )
    # fmt: on

    def score_message(message):
        """Score the message based on the presence of letters and common words."""
        score = 0
        words = message.lower().split()

        # Score based on letter presence
        letter_score = sum(1 for char in message.lower() if char in letters)

        # Score based on common words presence
        word_score = sum(1 for word in words if word in common_words)

        # Combine scores (you can adjust the weight of each component)
        return letter_score + (word_score * 2)  # Weight common words more heavily

    best_decrypted_list = []  # List to store best decrypted messages

    # Process each hex string in the list
    for hex_str in hex_lines_list:
        raw_bytes = bytes.fromhex(hex_str)

        best_score = 0
        best_decrypted_message = ""
        best_key = 0

        # Iterate over all possible single-byte keys (0 to 255)
        for key in range(256):
            # XOR each byte of raw_bytes with the current key
            decrypted_bytes = bytes([b ^ key for b in raw_bytes])
            # Decode the bytes to a string
            decrypted_message = decrypted_bytes.decode(
                errors="ignore"
            )  # Ignore errors for non-printable

            # Score the decrypted message
            current_score = score_message(decrypted_message)

            # Check if this score is better than the best score found so far
            if current_score > best_score:
                best_score = current_score
                best_decrypted_message = decrypted_message
                best_key = key

        # Store the best result for the current hex string in the list
        best_decrypted_list.append(
            {
                "hex": hex_str,
                "best_key": best_key,
                "decrypted_message": best_decrypted_message,
                "score": best_score,
            }
        )

    best_overall = max(best_decrypted_list, key=lambda x: x["score"])

    # Print the best result
    print(
        "Best Overall:\n"
        "Hex: {}\n"
        "Best Key: {} ('{}') -> Decrypted: {} with score: {}\n".format(
            best_overall["hex"],
            best_overall["best_key"],
            chr(best_overall["best_key"]),
            best_overall["decrypted_message"],
            best_overall["score"],
        )
    )


if __name__ == "__main__":
    detect_single_character_xor()
