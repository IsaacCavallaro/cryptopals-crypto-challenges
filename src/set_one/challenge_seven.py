from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from utils.helper_functions import convert_base64_to_bytes, convert_file_to_string

ENCRYPTED_FILE = "./src/set_one/challenge_seven_codes.txt"
KEY = "YELLOW SUBMARINE"


def decrypt_aes_ecb(encrypted_data: str, key: str) -> str:
    # Ensure the key length is 16 bytes (128 bits)
    key_bytes = key.encode("utf-8")

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding (PKCS7)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return unpadded_data.decode("utf-8")


if __name__ == "__main__":
    base64_encoded_content = convert_file_to_string(ENCRYPTED_FILE)
    encrypted_data = convert_base64_to_bytes(base64_encoded_content)

    # Decrypt the content
    decrypted_text = decrypt_aes_ecb(encrypted_data, KEY)
    print(decrypted_text)
