# Link to Challenge

- [Challenge Seven](https://www.cryptopals.com/sets/1/challenges/7)

---

# Challenge Seven  -> AES in ECB mode

- The Base64-encoded content in this [file](https://www.cryptopals.com/static/challenge-data/7.txt) has been encrypted via AES-128 in ECB mode under the key `"YELLOW SUBMARINE"`

- (case-sensitive, without the quotes; exactly 16 characters;
  - I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
- Decrypt it. You know the key, after all.

- Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

---

- 💡 You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
