import binascii
import hashlib
from hashlib import sha256
import re

import base58
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key as _ECDSA_Public_key
from ecdsa.ecdsa import Private_key as _ECDSA_Private_key
from ecdsa.ellipticcurve import Point as _ECDSA_Point

from bitmerchant.wallet.network import BitcoinMainNet


def is_hex_string(string):
    return re.match(r'[A-Fa-f0-9]+', string) is not None


def long_to_hex(l, size):
    f_str = "{0:0%sx}" % size
    return f_str.format(l).upper()


class ExtendedBip32Key(object):
    def is_extended_bip32_key(self, key):
        try:
            # See if we can unhexlify it
            unhex_key = binascii.unhexlify(key)
            return len(unhex_key) == 64
        except Exception:
            pass
        return len(key) == 128

    def is_hex(self, key):
        return len(key) == 130

    def is_compressed_hex(self, key):
        return len(key) == 66


class MasterPasswordKey(object):
    @classmethod
    def from_master_password(self, password, network):
        """Generate a new key from a master password.

        This password is hashed via 50,000 rounds of HMAC-SHA256.
        """


class AddressKey(object):
    """Utilities to generate a valid bitcoin/altcoin address from a key."""
    def hash160(self, data):
        """Return ripemd160(sha256(data))"""
        rh = hashlib.new('ripemd160', sha256(data).digest())
        return rh.digest()

    def to_address(self):
        """Create a public address from this key.

        https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
        """
        key = binascii.unhexlify(self.key)
        # First get the hash160 of the key
        hash160_bytes = self.hash160(key)
        # Prepend the network address byte
        network_hash160_bytes = \
            chr(self.network.ADDRESS_BYTE_PREFIX) + hash160_bytes
        # Return a base58 encoded address with a checksum
        return base58.b58encode_check(network_hash160_bytes)


class Key(object):
    def __init__(self, network):
        """Construct a Key."""
        # Set network first because set_key needs it
        self.network = network

    def __eq__(self, other):
        return (self.key == other.key and
                self.network == other.network and
                type(self) == type(other))

    def is_hex_bytes(self, key):
        if len(key) == 32 and not self.is_hex(key):
            try:
                binascii.hexlify(key)
                return True
            except Exception:
                pass
        return False

    def hex_bytes_to_hex(self, key):
        return binascii.hexlify(key)

    def is_hex(self, key):
        return (len(key) == 64 and
                re.match(r'[A-Fa-f0-9]+', key) is not None)

    @classmethod
    def decompress(self, key):
        "TODO"


class PrivateKey(Key):
    def __init__(self, private_exponent, network=BitcoinMainNet):
        if not isinstance(private_exponent, long):
            raise ValueError("private_exponent must be a long")
        super(PrivateKey, self).__init__(network)
        self.private_exponent = private_exponent
        pubkey = self.get_public_key()
        self.point = _ECDSA_Private_key(pubkey.point, long(self.key, 16))

    @property
    def key(self):
        return long_to_hex(self.private_exponent, 64)

    def get_public_key(self):
        g = SECP256k1.generator
        point = _ECDSA_Public_key(g, g * self.private_exponent).point
        return PublicKey.from_point(point, self.network)

    def get_extended_key(self):
        """Get the extended key.

        Extended keys contain the network bytes and the public or private
        key.
        """
        network_hex_chars = binascii.hexlify(
            chr(self.network.PRIVATE_KEY_BYTE_PREFIX))
        return network_hex_chars + self.key

    def export_to_wif(self):
        """Export a key to WIF.

        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Add the network byte, creating the "extended key"
        extended_key_hex = self.get_extended_key()
        extended_key_bytes = binascii.unhexlify(extended_key_hex)
        # And return the base58-encoded result with a checksum
        return base58.b58encode_check(extended_key_bytes)

    @classmethod
    def from_wif(cls, wif, network=BitcoinMainNet):
        """Import a key in WIF format.

        WIF is Wallet Import Format. It is a base58 encoded checksummed key.
        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Decode the base58 string and ensure the checksum is valid
        try:
            extended_key_bytes = base58.b58decode_check(wif)
        except ValueError as e:
            # Invalid checksum!
            raise ChecksumException(e)

        # Verify we're on the right network
        network_bytes = extended_key_bytes[0]
        if (ord(network_bytes) != network.PRIVATE_KEY_BYTE_PREFIX):
            raise incompatible_network_exception_factory(
                network_name=network.NAME,
                expected_prefix=network.PRIVATE_KEY_BYTE_PREFIX,
                given_prefix=ord(network_bytes))

        # Drop the network bytes
        extended_key_bytes = extended_key_bytes[1:]
        # And we should finally have a valid key
        return cls(long(binascii.hexlify(extended_key_bytes), 16), network)

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        if len(key) == 32:
            # Oh! we have bytes instead of a hex string
            key = binascii.hexlify(key)
        if not is_hex_string(key) or len(key) != 64:
            raise ValueError("Invalid hex key")
        return cls(long(key, 16), network)

    def __eq__(self, other):
        return (super(PrivateKey, self).__eq__(other) and
                self.private_exponent == other.private_exponent)


class ExtendedPrivateKey(PrivateKey, ExtendedBip32Key):
    def __init__(self, raw_key, network=BitcoinMainNet):
        self.depth = None
        self.fingerprint = None
        self.child_number = None
        self.chain_code = None
        super(ExtendedPrivateKey, self).__init__(raw_key, network)

    def parse_raw_key(self):
        pass


class PublicKey(Key, AddressKey):
    def __init__(self, x, y, network=BitcoinMainNet):
        """Create a public key.

        :param x: The x coordinate on the curve
        :type x: long
        :param y: The y coordinate on the curve
        :type y: long
        TODO: Support compressed pubkeys
        TODO: Use ECDSA Points?
        """
        super(PublicKey, self).__init__(network)
        self.x = x
        self.y = y
        self.point = self.create_point(x, y)

    @property
    def key(self):
        key = "{network}{x}{y}".format(
            network=binascii.hexlify(chr(self.network.PUBLIC_KEY_BYTE_PREFIX)),
            x=long_to_hex(self.x, 64),
            y=long_to_hex(self.y, 64))
        return key.upper()

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        """Return the key in hexlified nxy format.

        nxy format is a name I made up. The key consists of
          * 1 Byte network key
          * 32 Bytes x coordinate
          * 32 Bytes y cooddinate
        """
        if len(key) == 65:
            # It might be a byte array
            try:
                key = binascii.hexlify(key)
            except TypeError:
                pass

        if len(key) != 130:
            raise KeyParseError("The given key is not in a known format.")

        if len(key) == 130:
            # 1B network key + 32B x coord + 32B y coord = 65
            # ...and double 65 because two hex chars = 1 Byte
            network_key, x, y = (
                key[:2],
                key[2:64+2],
                key[64+2:])
            # Verify the network key matches the given network
            network_key_bytes = binascii.unhexlify(network_key)
            if ord(network_key_bytes) != network.PUBLIC_KEY_BYTE_PREFIX:
                raise incompatible_network_exception_factory(
                    network.NAME, network.PUBLIC_KEY_BYTE_PREFIX,
                    ord(network_key_bytes))
        return cls(long(x, 16), long(y, 16), network)

    def point_from_key(self, key):
        """Create an ECDSA Point from a key.

        This assumes `key` has already gone through `parse_raw_key`
        """
        _, x, y = key[:2], key[2:2+64], key[2+64:]
        return self.create_point(long(x, 16), long(y, 16))

    def create_point(self, x, y):
        if not isinstance(x, long) or not isinstance(y, long):
            raise ValueError("The coordinates must be longs.")
        return _ECDSA_Point(SECP256k1.curve, x, y)

    @classmethod
    def from_point(cls, point, network=BitcoinMainNet):
        """Create a PublicKey from an SECP256k1 point."""
        # A raw key is the network byte, followed by the 32B X and 32B Y coords
        return cls(point.x(), point.y(), network)


class KeyParseError(Exception):
    pass


def incompatible_network_exception_factory(
        network_name, expected_prefix, given_prefix):
    return IncompatibleNetworkException(
        "Incorrect network. {net_name} expects a byte prefix of "
        "{expected_prefix}, but you supplied {given_prefix}".format(
            net_name=network_name,
            expected_prefix=expected_prefix,
            given_prefix=given_prefix))


class ChecksumException(Exception):
    pass


class IncompatibleNetworkException(Exception):
    pass
