from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from set_one.challenge_seven import decrypt_aes_ecb

KEY = "YELLOW SUBMARINE"
TEXT = "Here is some plain text to encrypt, hopefully it works."
IV = r"\x00" * 16


def encrypt_aes_ecb(plain_data: str, key: str) -> str:
    # Ensure the key length is 16 bytes (128 bits)
    key_bytes = key.encode("utf-8")

    # Create an AES cipher object
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plain_data.encode("utf-8")) + padder.finalize()

    # Encrypt the padded data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data  # Return as a hex string for readability


if __name__ == "__main__":
    encrypteed_data = encrypt_aes_ecb(TEXT, KEY)
    print(encrypteed_data)
    decrypted_data = decrypt_aes_ecb(encrypteed_data, KEY)
    print(decrypted_data)


# Take decrypt_aes_ecb function from challenge 7 and make it encrypt
# Verify this by encrypte and decrypting
# USe XOR function
