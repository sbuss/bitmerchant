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


class HexKey(object):
    """Utilities for dealing with hex-encoded strings."""
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


class WIFKey(object):
    """Methods for dealing with WIF keys

    WIF is Wallet Import Format. It is a base58 encoded checksummed key.
    See https://en.bitcoin.it/wiki/Wallet_import_format for a full description.
    """
    def export_to_wif(self):
        """Export a key to WIF."""
        # First add the network byte, creating the "extended key"
        network_hex_chars = binascii.hexlify(
            chr(self.network.PRIVATE_KEY_BYTE_PREFIX))
        extended_key_hex = network_hex_chars + self.key
        extended_key_bytes = binascii.unhexlify(extended_key_hex)
        # And return the base58-encoded result with a checksum
        return base58.b58encode_check(extended_key_bytes)

    @classmethod
    def from_wif(cls, wif, network=BitcoinMainNet):
        """Import a key in WIF format."""
        # Decode the base58 string and ensure the checksum is valid
        try:
            extended_key_bytes = base58.b58decode_check(wif)
        except ValueError as e:
            # Invalid checksum!
            raise cls.ChecksumException(e)

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
        return cls(binascii.hexlify(extended_key_bytes), network)

    class ChecksumException(Exception):
        pass


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


class Key(HexKey):
    def __init__(self, raw_key, network):
        """Construct a Key.

        :param raw_key: The raw hex-encoded key
        :type raw_key: Hex string
        """
        # Set network first because set_key needs it
        self.network = network
        self.key = raw_key

    def get_key(self):
        """Get the key, as a hex string.

        The key is stored as a 'hexlified' string.
        """
        return self._key

    def set_key(self, key):
        self._key = self.parse_raw_key(key)

    key = property(get_key, set_key)

    def parse_raw_key(self, key):
        if self.is_hex_bytes(key):
            key = self.hex_bytes_to_hex(key)
        if self.is_hex(key):
            return key.upper()
        raise KeyParseError("Invaid key")

    def __eq__(self, other):
        return (self._key == other._key and
                self.network == other.network and
                type(self) == type(other))


class PrivateKey(Key, WIFKey):
    def __init__(self, raw_key, network=BitcoinMainNet):
        super(PrivateKey, self).__init__(raw_key, network)
        pubkey = self.get_public_key()
        self.point = _ECDSA_Private_key(pubkey.point, long(self.key, 16))

    def get_public_key(self):
        g = SECP256k1.generator
        point = _ECDSA_Public_key(g, g * long(self.key, 16)).point
        return PublicKey.from_point(point, self.network)


class PublicKey(Key, AddressKey):
    def __init__(self, raw_key, network=BitcoinMainNet):
        """Create a public key.

        :param raw_key: The 65-byte raw public key.
        :type raw_key: Public key hex string consisting of 65 bytes:
             * 1 byte 0x04
             * 32 bytes corresponding to X coordinate
             * 32 bytes corresponding to Y coordinate
        TODO: Support compressed pubkeys
        TODO: Use ECDSA Points?
        """
        super(PublicKey, self).__init__(raw_key, network)
        self.point = self.point_from_key(self.key)

    def parse_raw_key(self, key):
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
            if ord(network_key_bytes) != self.network.PUBLIC_KEY_BYTE_PREFIX:
                raise incompatible_network_exception_factory(
                    self.network.NAME, self.network.PUBLIC_KEY_BYTE_PREFIX,
                    ord(network_key_bytes))
        return key.upper()

    def point_from_key(self, key):
        """Create an ECDSA Point from a key.

        This assumes `key` has already gone through `parse_raw_key`
        """
        _, x, y = key[:2], key[2:2+64], key[2+64:]
        return _ECDSA_Point(SECP256k1.curve, long(x, 16), long(y, 16))

    @classmethod
    def from_point(cls, point, network=BitcoinMainNet):
        """Create a PublicKey from an SECP256k1 point."""
        # A raw key is the network byte, followed by the 32B X and 32B Y coords
        raw_key = "%s%x%x" % (
            binascii.hexlify(chr(network.PUBLIC_KEY_BYTE_PREFIX)),
            point.x(), point.y())
        return cls(raw_key, network)


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


class IncompatibleNetworkException(Exception):
    pass
