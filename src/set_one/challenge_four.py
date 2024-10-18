from typing import List, Dict, Union
from utils.helper_functions import (
    convert_hex_string_to_bytes,
    decrypt_message_with_key_and_score,
    update_best_key_if_needed,
    find_message_with_best_score,
    convert_file_to_list,
)


HEXADECIMALS_FILE = "./src/set_one/challenge_four_codes.txt"


def detect_single_character_xor() -> Dict[str, Union[str, int]]:
    hex_lines_list: List[str] = convert_file_to_list(HEXADECIMALS_FILE)
    best_decrypted_list: List[Dict[str, Union[str, int]]] = (
        []
    )  # List to store best decrypted messages

    # Process each hex string in the list
    for hex_str in hex_lines_list:
        raw_bytes = convert_hex_string_to_bytes(hex_str)

        best_score: int = 0
        best_decrypted_message: str = ""
        best_key: int = 0

        # Iterate over all possible single-byte keys (0 to 255)
        for key in range(256):
            current_score, decrypted_message = decrypt_message_with_key_and_score(
                key, raw_bytes
            )
            best_score, best_key, best_decrypted_message = update_best_key_if_needed(
                current_score,
                decrypted_message,
                key,
                best_score,
                best_key,
                best_decrypted_message,
            )

        # Store the best result for the current hex string in the list
        best_decrypted_list.append(
            {
                "hex": hex_str,
                "best_key": best_key,
                "decrypted_message": best_decrypted_message,
                "score": best_score,
            }
        )

    return find_message_with_best_score(best_decrypted_list)


if __name__ == "__main__":
    best_overall = detect_single_character_xor()
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
