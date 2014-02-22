from binascii import hexlify
from binascii import unhexlify
from collections import namedtuple
from hashlib import sha512
import hmac
import random

import base58
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key as _ECDSA_Public_key
from ecdsa.numbertheory import square_root_mod_prime

from bitmerchant.wallet.network import BitcoinMainNet
from bitmerchant.wallet.keys import incompatible_network_exception_factory
from bitmerchant.wallet.keys import PrivateKey
from bitmerchant.wallet.keys import PublicKey
from bitmerchant.wallet.utils import hash160
from bitmerchant.wallet.utils import is_hex_string
from bitmerchant.wallet.utils import long_to_hex


PublicPair = namedtuple("PublicPair", ["x", "y"])


class Wallet(object):
    """A BIP32 wallet is made up of Wallet nodes.

    A Private node contains both a public and private key, while a public
    node contains only a public key.

    **WARNING**:

    When creating a NEW wallet you MUST back up the private key. If
    you don't then any coins sent to your address will be LOST FOREVER.

    You need to save the private key somewhere. It is OK to just write
    it down on a piece of paper! Don't share this key with anyone!

    >>> my_wallet = Wallet.from_master_secret(
    ...     key='correct horse battery staple')
    >>> private = my_wallet.serialize(private=True)
    >>> private  # doctest: +ELLIPSIS
    u'xprv9s21ZrQH143K2mDJW8vDeFwbyDbFv868mM2Zr87rJSTj8q16Unkaq1pryiV...'

    If you want to use this wallet on your website to accept bitcoin or
    altcoin payments, you should first create a primary child.
    """
    def __init__(self,
                 chain_code,
                 depth=0,
                 parent_fingerprint=0L,
                 child_number=0L,
                 private_exponent=None,
                 public_pair=None,
                 network=BitcoinMainNet):
        """Construct a new BIP32 compliant wallet.

        You probably don't want to use this init methd. Instead use one
        of the 'from_master_secret' or 'deserialize' cosntructors.
        """
        if not private_exponent and not public_pair:
            raise ValueError(
                "You must supply one of private_exponent or public_pair")

        self.private_key = None
        self.public_key = None
        if private_exponent:
            self.private_key = PrivateKey(
                private_exponent, network=network)
        if public_pair:
            self.public_key = PublicKey(
                long(public_pair.x),
                long(public_pair.y),
                network=network)
            if (self.private_key and self.private_key.get_public_key() !=
                    self.public_key):
                raise ValueError(
                    "Provided private and public values do not match")
        else:
            self.public_key = self.private_key.get_public_key()

        def h(val, hex_len):
            if isinstance(val, long) or isinstance(val, int):
                return long_to_hex(val, hex_len)
            elif isinstance(val, basestring) and is_hex_string(val):
                if len(val) != hex_len:
                    raise ValueError("Invalid parameter length")
                return val
            else:
                raise ValueError("Invalid parameter type")

        self.network = network
        if not isinstance(depth, int) and not isinstance(depth, long):
            raise ValueError("depth must be an int or long")
        self.depth = depth
        if (isinstance(parent_fingerprint, basestring) and
                parent_fingerprint.startswith("0x")):
            parent_fingerprint = parent_fingerprint[2:]
        self.parent_fingerprint = h(parent_fingerprint, 8)
        self.child_number = h(child_number, 8)
        self.chain_code = h(chain_code, 64)

    def get_private_key_hex(self):
        """
        Get the hex-encoded (I guess SEC1?) representation of the private key.

        DO NOT share this private key with anyone.
        """
        return self.private_key.key

    def get_public_key_hex(self, compressed=True):
        """Get the sec1 representation of the public key.

        Note that I pieced this algorithm together from the pycoin source.

        This is documented in http://www.secg.org/collateral/sec1_final.pdf
        but, honestly, it's pretty confusing.

        I guess this is a pretty big warning that I'm not *positive* this
        will do the right thing in all cases. The tests pass, and this does
        exactly what pycoin does, but I'm not positive pycoin works either!
        """
        if compressed:
            parity = 2 + (self.public_key.y & 1)  # 0x02 even, 0x03 odd
            return (long_to_hex(parity, 2) +
                    long_to_hex(self.public_key.x, 32))
        else:
            return ('04' + long_to_hex(self.public_key.x, 32) +
                    long_to_hex(self.public_key.y, 32))

    @property
    def identifier(self):
        """Get the identifier for this node.

        Extended keys can be identified by the Hash160 (RIPEMD160 after SHA256)
        of the public key's `key`. This corresponds exactly to the data used in
        traditional Bitcoin addresses. It is not advised to represent this data
        in base58 format though, as it may be interpreted as an address that
        way (and wallet software is not required to accept payment to the chain
        key itself).
        """
        key = self.get_public_key_hex()
        return hexlify(hash160(unhexlify(key)))

    @property
    def fingerprint(self):
        """The first 32 bits of the identifier are called the fingerprint."""
        # 32 bits == 4 Bytes == 8 hex characters
        return hex(int(self.identifier[:8], 16))

    def create_new_address_for_user(self, user_id):
        """Create a new bitcoin address to accept payments for a User.

        This is a convenience wrapper around `get_child` that helps you do
        the right thing. This method always creates a public, non-prime
        address that can be generated from a BIP32 public key on an
        insecure server."""
        max_id = 0x80000000
        if user_id < 0 or user_id > max_id:
            raise ValueError(
                "Invalid UserID. Must be between 0 and %s" % max_id)
        return self.get_child(user_id, is_prime=False, as_private=False)

    def get_child(self, child_number, is_prime=None, as_private=True):
        """Derive a child key.

        :param child_number: The number of the child key to compute
        :type child_number: int
        :param is_prime: If set, determines if the resulting child is prime
        :type is_prime: bool, defaults to None
        :param as_private: If True, include private key in result. Defaults
            to True. If there is no private key present, this is ignored.
        :type as_private: bool

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

        This derivation is fully described at
        https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#child-key-derivation-functions  # nopep8
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

        if not self.private_key and is_prime:
            raise ValueError(
                "Cannot compute a prime child without a private key")

        if is_prime:
            # Even though we take child_number as an int < boundary, the
            # internal derivation needs it to be the larger number.
            child_number = child_number + boundary
        child_number_hex = long_to_hex(child_number, 8)

        if is_prime:
            # Let data = concat(0x00, self.key, child_number)
            data = '00' + self.private_key.key
        else:
            data = self.get_public_key_hex()
        data += child_number_hex

        # Compute a 64 Byte I that is the HMAC-SHA512, using self.chain_code
        # as the seed, and data as the message.
        I = hmac.new(
            unhexlify(self.chain_code),
            msg=unhexlify(data),
            digestmod=sha512).digest()
        # Split I into its 32 Byte components.
        I_L, I_R = I[:32], I[32:]

        c_i = hexlify(I_R)
        private_exponent = None
        public_pair = None
        if as_private and self.private_key:
            # Use private information for derivation
            # I_L is added to the current key's secret exponent (mod n), where
            # n is the order of the ECDSA curve in use.
            private_exponent = (
                (long(hexlify(I_L), 16) + long(self.private_key.key, 16))
                % SECP256k1.order)
            # I_R is the child's chain code
        else:
            # Only use public information for this derivation
            g = SECP256k1.generator
            I_L_long = long(hexlify(I_L), 16)
            point = (_ECDSA_Public_key(g, g * I_L_long).point +
                     self.public_key.point)
            # I_R is the child's chain code
            public_pair = PublicPair(point.x(), point.y())

        return self.__class__(
            chain_code=c_i,
            depth=self.depth + 1,  # we have to go deeper...
            parent_fingerprint=self.fingerprint,
            child_number=child_number_hex,
            private_exponent=private_exponent,
            public_pair=public_pair)

    def export_to_wif(self):
        """Export a key to WIF.

        See https://en.bitcoin.it/wiki/Wallet_import_format for a full
        description.
        """
        # Add the network byte, creating the "extended key"
        extended_key_hex = self.private_key.get_extended_key()
        # BIP32 wallets have a trailing \01 byte
        extended_key_bytes = unhexlify(extended_key_hex) + b'\01'
        # And return the base58-encoded result with a checksum
        return base58.b58encode_check(extended_key_bytes)

    def serialize(self, private=True, compressed=True):
        """Serialize this key.

        :param private: Whether or not the serialized key should contain
            private information. Set to False for a public-only representation
            that cannot spend funds but can create children. You want
            private=False if you are, for example, running an e-commerce
            website and want to accept bitcoin payments. See the README
            for more information.
        :type private: bool, defaults to True
        :param compressed: True if you want the public key compressed. False
            if not. Note that uncompressed keys are non-standard and might
            not be supported by other tools. You should pretty much always
            use compressed=True.
        :type compressed: bool, defaults to True

        See the spec in `deserialize` for more details.
        """
        if private and not self.private_key:
            raise ValueError("Cannot serialize a public key as private")

        if private:
            network_version = long_to_hex(
                self.network.EXTENDED_PRIVATE_BYTE_PREFIX, 8)
        else:
            network_version = long_to_hex(
                self.network.EXTENDED_PUBLIC_BYTE_PREFIX, 8)
        depth = long_to_hex(self.depth, 2)
        parent_fingerprint = self.parent_fingerprint
        child_number = self.child_number
        chain_code = self.chain_code
        ret = (network_version + depth + parent_fingerprint + child_number +
               chain_code)
        # Private and public serializations are slightly different
        if private:
            ret += '00' + self.private_key.key
        else:
            ret += self.get_public_key_hex(compressed)
        return ret.lower()

    def serialize_b58(self, private=True, compressed=True):
        """Encode the serialized node in base58."""
        return base58.b58encode_check(
            unhexlify(self.serialize(private, compressed)))

    def to_address(self):
        """Create a public address from this Node.

        Public addresses can accept payments.

        https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
        """
        key = unhexlify(self.get_public_key_hex())
        # First get the hash160 of the key
        hash160_bytes = hash160(key)
        # Prepend the network address byte
        network_hash160_bytes = \
            chr(self.network.PUBKEY_ADDRESS) + hash160_bytes
        # Return a base58 encoded address with a checksum
        return base58.b58encode_check(network_hash160_bytes)

    @classmethod
    def deserialize(cls, key, network=BitcoinMainNet):
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
              (Note that this also supports 0x04 + X + Y uncompressed points)
        """
        if len(key) == 78:
            # we have bytes
            key = hexlify(key)
        if not is_hex_string(key) or len(key) not in [78 * 2, (78 + 32) * 2]:
            raise ValueError("Invalid hex key. Might be base58? TODO")
        # Now that we double checkd the values, convert back to bytes because
        # they're easier to slice
        key = unhexlify(key)
        version, depth, parent_fingerprint, child, chain_code, key_data = (
            key[:4], key[4], key[5:9], key[9:13], key[13:45], key[45:])

        version_long = long(hexlify(version), 16)
        exponent = None
        public_pair = None
        if ord(key_data[0]) == 0:
            # Private key
            if version_long != network.EXTENDED_PRIVATE_BYTE_PREFIX:
                raise incompatible_network_exception_factory(
                    network.NAME, network.EXTENDED_PRIVATE_BYTE_PREFIX,
                    version)
            exponent = key_data[1:]
        elif ord(key_data[0]) in [2, 3, 4]:
            # Compressed public coordinates
            if version_long != network.EXTENDED_PUBLIC_BYTE_PREFIX:
                raise incompatible_network_exception_factory(
                    network.NAME, network.EXTENDED_PUBLIC_BYTE_PREFIX,
                    version)
            if ord(key_data[0]) == 4:
                # Uncompressed public point
                public_pair = PublicPair(
                    long(hexlify(key_data[1:33]), 16),
                    long(hexlify(key_data[33:]), 16))
            else:
                # Compressed public point!
                y_odd = bool(ord(key_data[0]) & 0x01)  # 0 even, 1 odd
                x = long(hexlify(key_data[1:]), 16)
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
            raise ValueError("Invalid key_data prefix. Expecting 0x00 + k, "
                             "got %s" % ord(key_data[0]))

        def l(byte_seq):
            if byte_seq is None:
                return byte_seq
            return long(hexlify(byte_seq), 16)

        return cls(depth=l(depth),
                   parent_fingerprint=l(parent_fingerprint),
                   child_number=l(child),
                   chain_code=l(chain_code),
                   private_exponent=l(exponent),
                   public_pair=public_pair,
                   network=network)

    @classmethod
    def from_master_secret(cls, seed, network=BitcoinMainNet):
        """Generate a new PrivateKey from a secret key.

        :param seed: The key to use to generate this wallet. It may be a long
            string. Do not use a phrase from a book or song, as that will
            be guessed and is not secure. My advice is to not supply this
            argument and let me generate a new random key for you.

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

    def __eq__(self, other):
        attrs = [
            'chain_code',
            'depth',
            'parent_fingerprint',
            'child_number',
            'private_key',
            'public_key',
            'network',
        ]
        return all(
            getattr(self, attr) == getattr(other, attr) for attr in attrs)

    @classmethod
    def new_random_wallet(cls, seed, network=BitcoinMainNet):
        """Generate a new wallet using a randomly generated 512 bit seed."""
        random_seed = random.randint(0, 2**512)
        random_hex_bytes = long_to_hex(random_seed, 512)
        return cls.from_master_secret(random_hex_bytes)
