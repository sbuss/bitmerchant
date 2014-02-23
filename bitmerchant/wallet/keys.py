from binascii import hexlify
from binascii import unhexlify
from collections import namedtuple
from hashlib import sha256
import hmac
import re

import base58
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key as _ECDSA_Public_key
from ecdsa.ecdsa import Private_key as _ECDSA_Private_key
from ecdsa.ellipticcurve import Point as _ECDSA_Point
from ecdsa.numbertheory import square_root_mod_prime

from bitmerchant.network import BitcoinMainNet
from bitmerchant.wallet.utils import hash160
from bitmerchant.wallet.utils import is_hex_string
from bitmerchant.wallet.utils import long_to_hex


PublicPair = namedtuple("PublicPair", ["x", "y"])


class Key(object):
    def __init__(self, network, compressed=False):
        """Construct a Key."""
        # Set network first because set_key needs it
        self.network = network
        self.compressed = compressed

    def __eq__(self, other):
        return (other and
                self.network == other.network and
                type(self) == type(other))

    def __ne__(self, other):
        return not self == other

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
        self.point = _ECDSA_Private_key(pubkey.point, long(self.get_key(), 16))

    def get_key(self):
        """Get the key - a hex formatted private exponent for the curve."""
        return long_to_hex(self.private_exponent, 64)

    def get_public_key(self):
        """Get the PublicKey for this PrivateKey."""
        g = SECP256k1.generator
        point = _ECDSA_Public_key(g, g * self.private_exponent).point
        return PublicKey.from_point(
            point, self.network, compressed=self.compressed)

    def get_extended_key(self):
        """Get the extended key.

        Extended keys contain the network bytes and the public or private
        key.
        """
        network_hex_chars = hexlify(
            chr(self.network.SECRET_KEY))
        return network_hex_chars + self.get_key()

    def export_to_wif(self, compressed=None):
        """Export a key to WIF.

        :param compressed: False if you want a standard WIF export (the most
            standard option). True if you want the compressed form (Note that
            not all clients will accept this form). Defaults to None, which
            in turn uses the self.compressed attribute.
        :type compressed: bool
        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Add the network byte, creating the "extended key"
        extended_key_hex = self.get_extended_key()
        extended_key_bytes = unhexlify(extended_key_hex)
        if compressed is None:
            compressed = self.compressed
        if compressed:
            extended_key_bytes += '\01'
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

        This supports compressed WIFs - see this for an explanation:
        http://bitcoin.stackexchange.com/questions/7299/when-importing-private-keys-will-compressed-or-uncompressed-format-be-used  # nopep8
        (specifically http://bitcoin.stackexchange.com/a/7958)
        """
        # Decode the base58 string and ensure the checksum is valid
        try:
            extended_key_bytes = base58.b58decode_check(wif)
        except ValueError as e:
            # Invalid checksum!
            raise ChecksumException(e)

        # Verify we're on the right network
        network_bytes = extended_key_bytes[0]
        if (ord(network_bytes) != network.SECRET_KEY):
            raise incompatible_network_exception_factory(
                network_name=network.NAME,
                expected_prefix=network.SECRET_KEY,
                given_prefix=ord(network_bytes))

        # Drop the network bytes
        extended_key_bytes = extended_key_bytes[1:]

        # Check for comprssed public key
        # This only affects the way in which addresses are generated.
        compressed = False
        if len(extended_key_bytes) == 33:
            # We are supposed to use compressed form!
            extended_key_bytes = extended_key_bytes[:-1]
            compressed = True

        # And we should finally have a valid key
        return cls(long(hexlify(extended_key_bytes), 16), network,
                   compressed=compressed)

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
                self.private_exponent == other.private_exponent and
                self.get_public_key() == other.get_public_key())


class PublicKey(Key):
    def __init__(self, x, y, network=BitcoinMainNet, *args, **kwargs):
        """Create a public key.

        :param x: The x coordinate on the curve
        :type x: long
        :param y: The y coordinate on the curve
        :type y: long
        :param network: The network you want (Networks just define certain
            constants, like byte-prefixes on public addresses).
        :type network: See `bitmerchant.wallet.network`
        """
        super(PublicKey, self).__init__(network=network, *args, **kwargs)
        if not isinstance(x, long) or not isinstance(y, long):
            raise ValueError("Coordinates must be longs")
        self.x = x
        self.y = y
        self.point = self.create_point(x, y)

    def get_key(self, compressed=None):
        """Get the hex-encoded key.

        :param compressed: False if you want a standard 65 Byte key (the most
            standard option). True if you want the compressed 33 Byte form.
            Defaults to None, which in turn uses the self.compressed attribute.
        :type compressed: bool

        PublicKeys consist of an ID byte, the x, and the y coordinates
        on the elliptic curve.

        In the case of uncompressed keys, the ID byte is 04.
        Compressed keys use the SEC1 format:
            If Y is odd: id_byte = 03
            else: id_byte = 02

        Note that I pieced this algorithm together from the pycoin source.

        This is documented in http://www.secg.org/collateral/sec1_final.pdf
        but, honestly, it's pretty confusing.

        I guess this is a pretty big warning that I'm not *positive* this
        will do the right thing in all cases. The tests pass, and this does
        exactly what pycoin does, but I'm not positive pycoin works either!
        """
        if compressed is None:
            compressed = self.compressed
        if compressed:
            parity = 2 + (self.y & 1)  # 0x02 even, 0x03 odd
            return (long_to_hex(parity, 2) +
                    long_to_hex(self.x, 64))
        else:
            return ('04' + long_to_hex(self.x, 64) +
                    long_to_hex(self.y, 64))

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        """Load the PublicKey from a compressed or uncompressed hex key.

        This format is defined in PublicKey.get_key()
        """
        if len(key) == 130 or len(key) == 66:
            # It might be a hexlified byte array
            try:
                key = unhexlify(key)
            except TypeError:
                pass

        compressed = False
        if ord(key[0]) == 4:
            # Uncompressed public point
            # 1B ID + 32B x coord + 32B y coord = 65 B
            if len(key) != 65:
                raise KeyParseError("Invalid key length")
            public_pair = PublicPair(
                long(hexlify(key[1:33]), 16),
                long(hexlify(key[33:]), 16))
        elif ord(key[0]) in [2, 3]:
            # Compressed public point!
            compressed = True
            if len(key) != 33:
                raise KeyParseError("Invalid key length")
            y_odd = bool(ord(key[0]) & 0x01)  # 0 even, 1 odd
            x = long(hexlify(key[1:]), 16)
            # The following x-to-pair algorithm was lifted from pycoin
            # I still need to sit down an understand it
            curve = SECP256k1.curve
            p = curve.p()
            alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
            beta = square_root_mod_prime(alpha, p)
            if y_odd:
                public_pair = PublicPair(x, beta)
            else:
                public_pair = PublicPair(x, p - beta)
        else:
            raise KeyParseError("The given key is not in a known format.")
        return cls.from_public_pair(public_pair, network=network,
                                    compressed=compressed)

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

    def to_address(self, compressed=None):
        """Create a public address from this key.

        :param compressed: False if you want a normal uncompressed address
            (the most standard option). True if you want the compressed form.
            Note that most clients will not accept compressed addresses.
            Defaults to None, which in turn uses the self.compressed attribute.
        :type compressed: bool

        https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
        """
        key = unhexlify(self.get_key(compressed))
        # First get the hash160 of the key
        hash160_bytes = hash160(key)
        # Prepend the network address byte
        network_hash160_bytes = \
            chr(self.network.PUBKEY_ADDRESS) + hash160_bytes
        # Return a base58 encoded address with a checksum
        return base58.b58encode_check(network_hash160_bytes)

    def to_public_pair(self):
        return PublicPair(self.x, self.y)

    @classmethod
    def from_public_pair(cls, pair, network=BitcoinMainNet, **kwargs):
        return cls(x=pair.x, y=pair.y, network=network, **kwargs)

    def __eq__(self, other):
        return (super(PublicKey, self).__eq__(other) and
                self.x == other.x and
                self.y == other.y)


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
