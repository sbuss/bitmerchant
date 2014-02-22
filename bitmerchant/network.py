class BitcoinMainNet(object):
    NAME = "Bitcoin Main Net"
    PUBLIC_KEY_BYTE_PREFIX = 0x04
    PUBKEY_ADDRESS = 0x00  # = int(0) --> '\0'
    SECRET_KEY = 0x80  # = int(128) --> "5"
    EXT_PUBLIC_KEY = 0x0488B21E
    EXT_PRIVATE_KEY = 0x0488ADE4


class BitcoinTestNet(object):
    NAME = "Bitcoin Test Net"
    # PUBLIC_KEY_BYTE_PREFIX = 0x04  TODO Verify this constant
    PUBKEY_ADDRESS = 0x6f  # = int(111) --> 'o'
    SECRET_KEY = 0xEF  # = int(239) --> "9"
    EXT_PUBLIC_KEY = 0x043587CF
    EXT_PRIVATE_KEY = 0x04358394


class DogecoinMainNet(object):
    PUBLIC_KEY_BYTE_PREFIX = 0x16  # int(0x16) --> 22
    PUBKEY_ADDRESS = 0x1e  # int(0x1e) --> 30 --> "D"
    SECRET_KEY = PUBLIC_KEY_BYTE_PREFIX + 128  # 30 + 128 = 158

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXT_PUBLIC_KEY = 0x02facafd
    EXT_PRIVATE_KEY = 0x02fac398


class DogecoinTestNet(object):
    PUBLIC_KEY_BYTE_PREFIX = 0xc4  # int(0xc4) --> 196
    PUBKEY_ADDRESS = 0x71  # int(0x71) --> 113
    SECRET_KEY = PUBLIC_KEY_BYTE_PREFIX + 128  # 30 + 128 = 158

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXT_PUBLIC_KEY = 0x0432a9a8
    EXT_PRIVATE_KEY = 0x0432a243
