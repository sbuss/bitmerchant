class BitcoinMainNet(object):
    NAME = "Bitcoin Main Net"
    PRIVATE_KEY_BYTE_PREFIX = 0x80  # = int(128) --> "5"
    PUBLIC_KEY_BYTE_PREFIX = 0x04
    ADDRESS_BYTE_PREFIX = 0x00  # = int(0) --> '\0'
    EXTENDED_PRIVATE_BYTE_PREFIX = 0x0488ADE4
    EXTENDED_PUBLIC_BYTE_PREFIX = 0x0488B21E


class BitcoinTestNet(object):
    NAME = "Bitcoin Test Net"
    PRIVATE_KEY_BYTE_PREFIX = 0xEF  # = int(239) --> "9"
    # PUBLIC_KEY_BYTE_PREFIX = 0x04  TODO Verify this constant
    ADDRESS_BYTE_PREFIX = 0x6f  # = int(111) --> 'o'
    EXTENDED_PRIVATE_BYTE_PREFIX = 0x04358394
    EXTENDED_PUBLIC_BYTE_PREFIX = 0x043587CF
