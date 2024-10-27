from set_two.challenge_nine import implement_pkcs_padding


def test_implement_pkcs_padding():
    assert (
        implement_pkcs_padding("YELLOW SUBMARINE", 20)
        == r"YELLOW SUBMARINE\0x4\0x4\0x4\0x4"
    )
    assert (
        implement_pkcs_padding("YELLOW SUBMARINE", 21)
        == r"YELLOW SUBMARINE\0x5\0x5\0x5\0x5\0x5"
    )
