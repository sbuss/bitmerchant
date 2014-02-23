class BitcoinMainNet(object):
    """Bitcoin MainNet version bytes.

    From https://github.com/bitcoin/bitcoin/blob/v0.9.0rc1/src/chainparams.cpp
    """
    NAME = "Bitcoin Main Net"
    SCRIPT_ADDRESS = 0x05  # int(0x05) = 5
    PUBKEY_ADDRESS = 0x00  # int(0x00) = 0  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488B21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses


class BitcoinTestNet(object):
    """Bitcoin TestNet version bytes.

    From https://github.com/bitcoin/bitcoin/blob/v0.9.0rc1/src/chainparams.cpp
    """
    NAME = "Bitcoin Test Net"
    SCRIPT_ADDRESS = 0xc4  # int(0xc4) = 196
    PUBKEY_ADDRESS = 0x6f  # int(0x6f) = 111
    SECRET_KEY = 0xEF      # int(0xef) = 239
    EXT_PUBLIC_KEY = 0x043587CF
    EXT_SECRET_KEY = 0x04358394


class LitecoinMainNet(object):
    """Litecoin MainNet version bytes

    Primary version bytes from:
    https://github.com/litecoin-project/litecoin/blob/master-0.8/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=453395.0
    """
    NAME = "Litecoin Main Net"
    SCRIPT_ADDRESS = 0x05  # int(0x05) = 5
    PUBKEY_ADDRESS = 0x30  # int(0x30) = 48
    SECRET_KEY = PUBKEY_ADDRESS + 128  # = int(0xb0) = 176

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=453395.0
    EXT_PUBLIC_KEY = 0x019da462
    EXT_SECRET_KEY = 0x019d9cfe


class LitecoinTestNet(object):
    """Litecoin TestNet version bytes

    Primary version bytes from:
    https://github.com/litecoin-project/litecoin/blob/master-0.8/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=453395.0
    """
    NAME = "Litecoin Test Net"
    SCRIPT_ADDRESS = 0xc4  # int(0xc4) = 196
    PUBKEY_ADDRESS = 0x6f  # int(0x6f) = 111
    SECRET_KEY = PUBKEY_ADDRESS + 128  # = int(0xef) = 239

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=453395.0
    EXT_PUBLIC_KEY = 0x0436f6e1
    EXT_SECRET_KEY = 0x0436ef7d


class DogecoinMainNet(object):
    """Dogecoin MainNet version bytes

    Primary version bytes from:
    https://github.com/dogecoin/dogecoin/blob/1.5.2/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=409731
    """
    NAME = "Dogecoin Main Net"
    SCRIPT_ADDRESS = 0x16  # int(0x16) = 22
    PUBKEY_ADDRESS = 0x1e  # int(0x1e) = 30
    SECRET_KEY = PUBKEY_ADDRESS + 128  # int(0x9e) = 158

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXT_PUBLIC_KEY = 0x02facafd
    EXT_SECRET_KEY = 0x02fac398


class DogecoinTestNet(object):
    """Dogecoin TestNet version bytes

    Primary version bytes from:
    https://github.com/dogecoin/dogecoin/blob/1.5.2/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=409731
    """
    NAME = "Dogecoin Test Net"
    SCRIPT_ADDRESS = 0xc4  # int(0xc4) = 196
    PUBKEY_ADDRESS = 0x71  # int(0x71) = 113
    SECRET_KEY = PUBKEY_ADDRESS + 128  # int(0xf1) = 241

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXT_PUBLIC_KEY = 0x0432a9a8
    EXT_SECRET_KEY = 0x0432a243
