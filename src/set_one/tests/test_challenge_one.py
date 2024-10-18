from set_one.challenge_one import hex_to_base64


def test_valid_hex_to_base64():
    assert (
        hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        )
        == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )

    assert hex_to_base64("f6f6") == "9vY="
