# Link to Challenge

- [Challenge Eight](https://www.cryptopals.com/sets/1/challenges/8)

---

# Challenge Eight  -> Detect AES in ECB mode

#

- [In this file](https://www.cryptopals.com/static/challenge-data/8.txt) are a bunch of hex-encoded ciphertexts.
- One of them has been encrypted with ECB.
- Detect it.
- Remember that the problem with ECB is that it is:
  - Stateless and deterministic
  - The same 16 byte plaintext block will always produce the same 16 byte ciphertext.
