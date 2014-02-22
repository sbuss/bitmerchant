class BitcoinMainNet(object):
    NAME = "Bitcoin Main Net"
    PUBLIC_KEY_BYTE_PREFIX = 0x04
    PUBKEY_ADDRESS = 0x00  # = int(0) --> '\0'
    PRIVATE_KEY_BYTE_PREFIX = 0x80  # = int(128) --> "5"
    EXTENDED_PUBLIC_BYTE_PREFIX = 0x0488B21E
    EXTENDED_PRIVATE_BYTE_PREFIX = 0x0488ADE4


class BitcoinTestNet(object):
    NAME = "Bitcoin Test Net"
    # PUBLIC_KEY_BYTE_PREFIX = 0x04  TODO Verify this constant
    PUBKEY_ADDRESS = 0x6f  # = int(111) --> 'o'
    PRIVATE_KEY_BYTE_PREFIX = 0xEF  # = int(239) --> "9"
    EXTENDED_PUBLIC_BYTE_PREFIX = 0x043587CF
    EXTENDED_PRIVATE_BYTE_PREFIX = 0x04358394


class DogecoinMainNet(object):
    PUBLIC_KEY_BYTE_PREFIX = 0x16  # int(0x16) --> 22
    PUBKEY_ADDRESS = 0x1e  # int(0x1e) --> 30 --> "D"
    PRIVATE_KEY_BYTE_PREFIX = PUBLIC_KEY_BYTE_PREFIX + 128  # 30 + 128 = 158

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXTENDED_PUBLIC_BYTE_PREFIX = 0x02facafd
    EXTENDED_PRIVATE_BYTE_PREFIX = 0x02fac398


class DogecoinTestNet(object):
    PUBLIC_KEY_BYTE_PREFIX = 0xc4  # int(0xc4) --> 196
    PUBKEY_ADDRESS = 0x71  # int(0x71) --> 113
    PRIVATE_KEY_BYTE_PREFIX = PUBLIC_KEY_BYTE_PREFIX + 128  # 30 + 128 = 158

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXTENDED_PUBLIC_BYTE_PREFIX = 0x0432a9a8
    EXTENDED_PRIVATE_BYTE_PREFIX = 0x0432a243
