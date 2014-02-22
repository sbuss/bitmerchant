from binascii import hexlify
from binascii import unhexlify
from hashlib import sha256
import hmac
import re

import base58
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key as _ECDSA_Public_key
from ecdsa.ecdsa import Private_key as _ECDSA_Private_key
from ecdsa.ellipticcurve import Point as _ECDSA_Point

from bitmerchant.wallet.network import BitcoinMainNet
from bitmerchant.wallet.utils import hash160
from bitmerchant.wallet.utils import is_hex_string
from bitmerchant.wallet.utils import long_to_hex


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
                hexlify(key)
                return True
            except Exception:
                pass
        return False

    def hex_bytes_to_hex(self, key):
        return hexlify(key)

    def is_hex(self, key):
        return (len(key) == 64 and
                re.match(r'[A-Fa-f0-9]+', key) is not None)

    @classmethod
    def decompress(self, key):
        "TODO"


class PrivateKey(Key):
    def __init__(self, private_exponent, network=BitcoinMainNet,
                 *args, **kwargs):
        if not isinstance(private_exponent, long):
            raise ValueError("private_exponent must be a long")
        super(PrivateKey, self).__init__(network=network, *args, **kwargs)
        self.private_exponent = private_exponent
        pubkey = self.get_public_key()
        self.point = _ECDSA_Private_key(pubkey.point, long(self.key, 16))

    @property
    def key(self):
        """Get the key - a hex formatted private exponent for the curve."""
        return long_to_hex(self.private_exponent, 64)

    def get_public_key(self):
        """Get the PublicKey for this PrivateKey."""
        g = SECP256k1.generator
        point = _ECDSA_Public_key(g, g * self.private_exponent).point
        return PublicKey.from_point(point, self.network)

    def get_extended_key(self):
        """Get the extended key.

        Extended keys contain the network bytes and the public or private
        key.
        """
        network_hex_chars = hexlify(
            chr(self.network.PRIVATE_KEY_BYTE_PREFIX))
        return network_hex_chars + self.key

    def export_to_wif(self):
        """Export a key to WIF.

        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Add the network byte, creating the "extended key"
        extended_key_hex = self.get_extended_key()
        extended_key_bytes = unhexlify(extended_key_hex)
        # And return the base58-encoded result with a checksum
        return base58.b58encode_check(extended_key_bytes)

    def _public_child(child_number):
        raise NotImplementedError()

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
        return cls(long(hexlify(extended_key_bytes), 16), network)

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        if len(key) == 32:
            # Oh! we have bytes instead of a hex string
            key = hexlify(key)
        if not is_hex_string(key) or len(key) != 64:
            raise ValueError("Invalid hex key")
        return cls(long(key, 16), network)

    @classmethod
    def from_master_password(cls, password, network=BitcoinMainNet):
        """Generate a new key from a master password.

        This password is hashed via a single round of sha256 and is highly
        breakable, but it's the standard brainwallet approach.

        See `PrivateKey.from_master_password_slow` for a slightly more
        secure generation method (which will still be subject to a rainbow
        table attack :\)
        """
        key = sha256(password).hexdigest()
        return cls.from_hex_key(key, network)

    @classmethod
    def from_master_password_slow(cls, password, network=BitcoinMainNet):
        """
        Generate a new key from a password using 50,000 rounds of HMAC-SHA256.

        This should generate the same result as bip32.org.

        WARNING: This is not yet tested.
        """
        # Make sure the password string is bytes
        key = password.encode('utf-8')
        for i in xrange(50000):
            key = hmac.new(key, digestmod=sha256).digest()
        return cls.from_hex_key(key, network)

    def __eq__(self, other):
        return (super(PrivateKey, self).__eq__(other) and
                self.private_exponent == other.private_exponent)


class PublicKey(Key):
    def __init__(self, x, y, network=BitcoinMainNet):
        """Create a public key.

        :param x: The x coordinate on the curve
        :type x: long
        :param y: The y coordinate on the curve
        :type y: long
        :param network: The network you want (Networks just define certain
            constants, like byte-prefixes on public addresses).
        :type network: See `bitmerchant.wallet.network`
        TODO: Support compressed pubkeys
        """
        super(PublicKey, self).__init__(network=network)
        if not isinstance(x, long) or not isinstance(y, long):
            raise ValueError("Coordinates must be longs")
        self.x = x
        self.y = y
        self.point = self.create_point(x, y)

    @property
    def key(self):
        """Get the hex-encoded key.

        PublicKeys consist of a network byte, the x, and the y coordinates
        on the elliptic curve.
        """
        key = "{network}{x}{y}".format(
            network=hexlify(chr(self.network.PUBLIC_KEY_BYTE_PREFIX)),
            x=long_to_hex(self.x, 64),
            y=long_to_hex(self.y, 64))
        return key.lower()

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        """Return the key in hexlified nxy format.

        nxy format is a name I made up, it's the same as PublicKey.key.
        The key consists of
          * 1 Byte network key
          * 32 Bytes x coordinate
          * 32 Bytes y cooddinate
        """
        if len(key) == 65:
            # It might be a byte array
            try:
                key = hexlify(key)
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
            network_key_bytes = unhexlify(network_key)
            if ord(network_key_bytes) != network.PUBLIC_KEY_BYTE_PREFIX:
                raise incompatible_network_exception_factory(
                    network.NAME, network.PUBLIC_KEY_BYTE_PREFIX,
                    ord(network_key_bytes))
        return cls(x=long(x, 16), y=long(y, 16), network=network)

    def point_from_key(self, key):
        """Create an ECDSA Point from a key.

        :param key: The public key
        :type key: A hex-encoded public key. See PublicKey.key
        """
        _, x, y = key[:2], key[2:2+64], key[2+64:]
        return self.create_point(long(x, 16), long(y, 16))

    def create_point(self, x, y):
        """Create an ECDSA point on the SECP256k1 curve with the given coords.

        :param x: The x coordinate on the curve
        :type x: long
        :param y: The y coodinate on the curve
        :type y: long
        """
        if not isinstance(x, long) or not isinstance(y, long):
            raise ValueError("The coordinates must be longs.")
        return _ECDSA_Point(SECP256k1.curve, x, y)

    @classmethod
    def from_point(cls, point, network=BitcoinMainNet, **kwargs):
        """Create a PublicKey from a point on the SECP256k1 curve.

        :param point: A point on the SECP256k1 curve.
        :type point: SECP256k1.point
        """
        return cls(x=point.x(), y=point.y(), network=network, **kwargs)

    def to_address(self):
        """Create a public address from this key.

        https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
        """
        key = unhexlify(self.key)
        # First get the hash160 of the key
        hash160_bytes = hash160(key)
        # Prepend the network address byte
        network_hash160_bytes = \
            chr(self.network.PUBKEY_ADDRESS) + hash160_bytes
        # Return a base58 encoded address with a checksum
        return base58.b58encode_check(network_hash160_bytes)


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


class InvalidChildException(Exception):
    pass
