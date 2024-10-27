PLAIN_TEXT = "YELLOW SUBMARINE"


def implement_pkcs_padding(text, fixed_block_size):
    diff_to_pad = fixed_block_size - len(text)
    hex_diff = hex(diff_to_pad)
    single_pad = f"\\{hex_diff}"

    for i in range(diff_to_pad):
        text += single_pad

    return text


if __name__ == "__main__":
    padded_text = implement_pkcs_padding(PLAIN_TEXT, 20)
    print(padded_text)
