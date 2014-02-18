from binascii import hexlify
from binascii import unhexlify
from hashlib import sha256
from hashlib import sha512
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


class ExtendedBip32Key(Key):
    def __init__(self,
                 chain_code,
                 depth=0,
                 parent_fingerprint=0L,
                 child_number=0L,
                 network=BitcoinMainNet,
                 *args, **kwargs):
        def h(val, hex_len):
            if isinstance(val, long) or isinstance(val, int):
                return long_to_hex(val, hex_len)
            elif isinstance(val, basestring) and is_hex_string(val):
                if len(val) != hex_len:
                    raise ValueError("Invalid parameter length")
                return val
            else:
                raise ValueError("Invalid parameter type")

        if not isinstance(depth, int) and not isinstance(depth, long):
            raise ValueError("depth must be an int or long")
        self.depth = depth
        if (isinstance(parent_fingerprint, basestring) and
                parent_fingerprint.startswith("0x")):
            parent_fingerprint = parent_fingerprint[2:]
        self.parent_fingerprint = h(parent_fingerprint, 8)
        self.child_number = h(child_number, 8)
        self.chain_code = h(chain_code, 64)
        super(ExtendedBip32Key, self).__init__(
            network=network, *args, **kwargs)

    def is_extended_bip32_key(self, key):
        try:
            # See if we can unhexlify it
            unhex_key = unhexlify(key)
            return len(unhex_key) == 64
        except Exception:
            pass
        return len(key) == 128

    def is_hex(self, key):
        return len(key) == 130

    def is_compressed_hex(self, key):
        return len(key) == 66

    def get_network_version(self):
        raise NotImplementedError()

    @property
    def identifier(self):
        """Get the identifier for the key.

        Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256)
        of the public key's `key`. This corresponds exactly to the data used in
        traditional Bitcoin addresses. It is not advised to represent this data
        in base58 format though, as it may be interpreted as an address that
        way (and wallet software is not required to accept payment to the chain
        key itself).
        """
        key = self.get_public_key().key
        return hexlify(hash160(unhexlify(key)))

    @property
    def fingerprint(self):
        """The first 32 bits of the identifier are called the fingerprint."""
        # 32 bits == 4 Bytes == 8 hex characters
        return hex(int(self.identifier[:8], 16))

    def _serialize_header(self, with_chain_code=True):
        network_version = long_to_hex(self.get_network_version(), 8)
        depth = long_to_hex(self.depth, 2)
        parent_fingerprint = self.parent_fingerprint
        child_number = self.child_number
        if with_chain_code:
            chain_code = self.chain_code
        else:
            chain_code = ""
        return (network_version + depth + parent_fingerprint + child_number +
                chain_code)

    def serialize(self, with_chain_code=True):
        """Serialize this key.

        See the spec in `from_hex_key` for details."""
        # Private and public serializations are slightly different, but the
        # header will be the same.
        header = self._serialize_header(with_chain_code)  # NOQA
        raise NotImplementedError()

    def serialize_b58(self):
        return base58.b58encode_check(unhexlify(self.serialize()))

    def get_child(self, child_number, is_prime=None):
        """Derive a child key.

        :param child_number: The number of the child key to compute
        :type child_number: int
        :param is_prime: If set, determines if the resulting child is prime
        :type is_prime: bool, defaults to None

        Positive child_numbers (less than 2,147,483,648) produce public
        children. Public children can only create other public children, and
        cannot spend any funds.

        Negative numbers (or numbers between 2,147,483,648 & 4,294,967,295)
        produce private children. Private children can create more private
        keys, spend the funds in its associated public key, and spend all funds
        from subsequent children, so should be kept safe.

        NOTE: Python can't do -0, so if you want the private 0th child you
        need to manually set is_prime=True.

        NOTE: negative numbered children are provided as a convenience
        because nobody wants to remember the above numbers. Negative numbers
        are considered 'prime children', which is described in the BIP32 spec
        as a leading 1 in a 32 bit unsigned int.
        """
        boundary = 0x80000000
        max_child = 0xFFFFFFFF

        # If is_prime isn't set, then we can infer it from the child_number
        if is_prime is None:
            if child_number > max_child or child_number < -1 * boundary:
                raise ValueError("Invalid child number")
            # Prime children are either < 0 or > 0x80000000
            if child_number < 0:
                child_number = abs(child_number)
                is_prime = True
            elif child_number >= boundary:
                child_number -= boundary
                is_prime = True
            else:
                is_prime = False
        else:
            # Otherwise is_prime is set so the child_number should be between
            # 0 and 0x80000000
            if child_number < 0 or child_number > boundary:
                raise ValueError("Invalid child number")
        if is_prime:
            return self._private_child(child_number)
        else:
            return self._public_child(child_number)

    def _private_child(self, child_number):
        raise NotImplementedError()

    def _public_child(self, child_number):
        raise NotImplementedError()

    @classmethod
    def _parse_raw_key(cls, key, network=BitcoinMainNet):
        """See `from_hex_key`
        TODO
        """
        if len(key) == 78:
            # we have bytes
            key = hexlify(key)
        if not is_hex_string(key) or len(key) != 78 * 2:
            raise ValueError("Invalid hex key")
        # Now that we double checkd the values, convert back to bytes because
        # they're easier to slice
        key = unhexlify(key)
        version, depth, parent_fingerprint, child, chain_code, key_data = (
            key[:4], key[4], key[5:9], key[9:13], key[13:45], key[45:])
        return (version, depth, parent_fingerprint, child, chain_code,
                key_data)

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        """Load the ExtendedBip32Key from a hex key.

        The key consists of

            * 4 byte version bytes (network key)
            * 1 byte depth:
                - 0x00 for master nodes,
                - 0x01 for level-1 descendants, ....
            * 4 byte fingerprint of the parent's key (0x00000000 if master key)
            * 4 byte child number. This is the number i in x_i = x_{par}/i,
              with x_i the key being serialized. This is encoded in MSB order.
              (0x00000000 if master key)
            * 32 bytes: the chain code
            * 33 bytes: the public key or private key data
              (0x02 + X or 0x03 + X for public keys, 0x00 + k for private keys)
        """
        # You'll want to start with this line probably
        version, depth, parent_fingerprint, child, chain_code, key_data = (
            cls._parse_raw_key(key, network))
        raise NotImplementedError()


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


class ExtendedPrivateKey(ExtendedBip32Key, PrivateKey):
    def get_network_version(self):
        return self.network.EXTENDED_PRIVATE_BYTE_PREFIX

    def get_public_key(self):
        """Get the PublicKey for this PrivateKey."""
        g = SECP256k1.generator
        point = _ECDSA_Public_key(g, g * self.private_exponent).point
        return ExtendedPublicKey.from_point(
            point, network=self.network, chain_code=self.chain_code,
            depth=self.depth, parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number)

    def export_to_wif(self):
        """Export a key to WIF.

        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Add the network byte, creating the "extended key"
        extended_key_hex = self.get_extended_key()
        extended_key_bytes = unhexlify(extended_key_hex) + b'\01'
        # And return the base58-encoded result with a checksum
        return base58.b58encode_check(extended_key_bytes)

    def _private_child(self, child_number):
        """Derive a private child for this key.

        This derivation is described at
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-child-key-derivation  # nopep8
        """
        boundary = 0x80000000
        if child_number < 0 or child_number >= boundary:
            raise ValueError("Invalid child number")

        # Even though we take child_number as an int < boundary, the internal
        # derivation needs it to be the larger number.
        child_number = child_number + boundary
        child_number_hex = long_to_hex(child_number, 8)
        # Let data = concat(0x00, self.key, child_number)
        data = '00' + self.key + child_number_hex
        # Compute a 64 Byte I that is the HMAC-SHA512, using self.chain_code
        # as the seed, and data as the message.
        I = hmac.new(
            unhexlify(self.chain_code),
            msg=unhexlify(data),
            digestmod=sha512).digest()
        # Split I into its 32 Byte components.
        I_L, I_R = I[:32], I[32:]
        # I_L is added to the current key's secret exponent (mod n), where
        # n is the order of the ECDSA curve in use.
        k_i = (long(hexlify(I_L), 16) + long(self.key, 16)) % SECP256k1.order
        # I_R is the child's chain code
        c_i = hexlify(I_R)
        return self.__class__(
            chain_code=c_i,
            depth=self.depth + 1,  # we have to go deeper...
            parent_fingerprint=self.fingerprint,
            child_number=child_number_hex,
            private_exponent=k_i)

    def _public_child(self, child_number):
        """Derive a public child for this key.

        This derivation is described at
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-child-key-derivation  # nopep8
        """
        boundary = 0x80000000
        if child_number < 0 or child_number >= boundary:
            raise ValueError("Invalid child number")

        child_number_hex = long_to_hex(child_number, 8)
        # Let data = the public key's compressed format + child_number
        data = self.get_public_key().key + child_number_hex
        # Compute a 64 Byte I that is the HMAC-SHA512, using self.chain_code
        # as the seed, and data as the message.
        I = hmac.new(
            unhexlify(self.chain_code),
            msg=unhexlify(data),
            digestmod=sha512).digest()
        # Split I into its 32 Byte components.
        I_L, I_R = I[:32], I[32:]
        # I_L is added to the current key's secret exponent (mod n), where
        # n is the order of the ECDSA curve in use.
        k_i = (long(hexlify(I_L), 16) + long(self.key, 16)) % SECP256k1.order
        # I_R is the child's chain code
        c_i = hexlify(I_R)
        return self.__class__(
            chain_code=c_i,
            depth=self.depth + 1,  # we have to go deeper...
            parent_fingerprint=self.fingerprint,
            child_number=child_number_hex,
            private_exponent=k_i)

    @classmethod
    def from_master_secret(cls, seed, network=BitcoinMainNet):
        """Generate a new PrivateKey from a secret key.

        See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format  # nopep8
        """
        # Given a seed S of at least 128 bits, but 256 is advised
        # Calculate I = HMAC-SHA512(key="Bitcoin seed", msg=S)
        I = hmac.new(b"Bitcoin seed", msg=seed, digestmod=sha512).digest()
        # Split I into two 32-byte sequences, IL and IR.
        I_L, I_R = I[:32], I[32:]
        # Use IL as master secret key, and IR as master chain code.
        return cls(private_exponent=long(hexlify(I_L), 16),
                   chain_code=long(hexlify(I_R), 16),
                   network=network)

    @classmethod
    def from_hex_key(cls, key, network=BitcoinMainNet):
        version, depth, parent_fingerprint, child, chain_code, key_data = (
            cls._parse_raw_key(key, network))

        if ord(key_data[0]) != 0:
            raise ValueError("Invalid key_data prefix. Expecting 0x00 + k, "
                             "got %s" % ord(key_data[0]))

        def l(byte_seq):
            return long(hexlify(byte_seq), 16)

        ret_val = cls(depth=l(depth),
                      parent_fingerprint=l(parent_fingerprint),
                      child_number=l(child),
                      chain_code=l(chain_code),
                      private_exponent=l(key_data[1:]),
                      network=network)

        if l(version) != ret_val.get_network_version():
            raise incompatible_network_exception_factory(
                network_name=network.NAME,
                expected_prefix=ret_val.get_network_version(),
                given_prefix=ord(version))
        return ret_val

    def serialize(self, with_chain_code=True):
        header = self._serialize_header(with_chain_code)
        header += '00' + self.key
        return header.lower()


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
            chr(self.network.ADDRESS_BYTE_PREFIX) + hash160_bytes
        # Return a base58 encoded address with a checksum
        return base58.b58encode_check(network_hash160_bytes)


class ExtendedPublicKey(ExtendedBip32Key, PublicKey):
    def get_network_version(self):
        return self.network.EXTENDED_PUBLIC_BYTE_PREFIX

    def get_public_key(self):
        return self

    def _private_child(self, child_number):
        raise InvalidChildException()

    def _public_child(self, child_number):
        boundary = 0x80000000
        if child_number < 0 or child_number >= boundary:
            raise ValueError("Invalid child number")

        child_number_hex = long_to_hex(child_number, 8)
        # Let data = the public key's compressed format + child_number
        data = self.key + child_number_hex
        # Compute a 64 Byte I that is the HMAC-SHA512, using self.chain_code
        # as the seed, and data as the message.
        I = hmac.new(
            unhexlify(self.chain_code),
            msg=unhexlify(data),
            digestmod=sha512).digest()
        # Split I into its 32 Byte components.
        I_L, I_R = I[:32], I[32:]
        # K_i = (I_L + k_par)*G = I_L*G + K_par
        g = SECP256k1.generator
        I_L_long = long(hexlify(I_L), 16)
        point = _ECDSA_Public_key(g, g * I_L_long).point + self.point
        # I_R is the child's chain code
        c_i = hexlify(I_R)
        return self.from_point(
            point=point,
            chain_code=c_i,
            depth=self.depth + 1,  # we have to go deeper...
            parent_fingerprint=self.fingerprint,
            child_number=child_number_hex)

    @property
    def key(self):
        # 0x03 for non-compressed points
        return '03' + long_to_hex(self.x, 32)

    def serialize(self, with_chain_code=True):
        header = self._serialize_header(with_chain_code)
        header += self.key
        return header.lower()


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
