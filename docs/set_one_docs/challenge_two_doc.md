# Link to Challenge

- [Challenge Two](https://www.cryptopals.com/sets/1/challenges/2)

---

# Challenge Two  -> Fixed XOR

- Write a function that takes two equal-length buffers and produces their XOR combination.
- If your function works properly, then when you feed it the string:

```
1c0111001f010100061a024b53535009181c
```

- after hex decoding, and when XOR'd against:

```
686974207468652062756c6c277320657965
```

- should produce:

```
746865206b696420646f6e277420706c6179
```

---

<aside>
💡 "equal-length buffers" means that after you decode both hex strings to raw bytes, they must have the same number of bytes for the XOR operation to work.

</aside>
