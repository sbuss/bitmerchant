from hashlib import sha256
import string
import random

from mock import patch

from pycoin import wallet


class _Wallet(wallet.Wallet):
    @classmethod
    def new_wallet(cls, key=None):
        """Create a new BIP32 compliant Wallet.

        Args:
            key: The key to use to generate this wallet. It may be a long
                string. Do not use a phrase from a book or song, as that will
                be guessed and is not secure. My advice is to not supply this
                argument and let me generate a new random key for you.

        **WARNING**:

        When creating a new wallet you MUST back up the private key. If
        you don't then any coins sent to your address will be LOST FOREVER.

        You need to save the private key somewhere. It is OK to just write
        it down on a piece of paper! Don't share this key with anyone!

            >>> my_wallet = BitcoinWallet.new_wallet(
            ...     key='correct horse battery staple')
            >>> private, public = my_wallet.get_keys()
            >>> private  # doctest: +ELLIPSIS
            u'xprv9s21ZrQH143K2mDJW8vDeFwbyDbFv868mM2Zr87rJSTj8q16Unka...'
        """
        key = key or cls._random_wallet_secret()
        return cls.from_master_secret(key)

    @classmethod
    def _random_wallet_secret(cls, size=1024, chars=string.printable):
        """Generate a random key for a wallet.

        TODO: Verify that this is a good idea.
        """
        return (sha256(''.join(random.choice(chars) for x in xrange(size)))
                .hexdigest())

    @classmethod
    def create_address(cls, master_pub_key, address_id):
        """Create a new address from a public key.

        Args:
            master_pub_key: A master public key for a wallet generated by
                wallet.Wallet.public_copy()
            address_id: The ID of the user you want to generate an address for.
                Address IDs should be positive integers that can be associated
                with the account that you're creating an address for.

        >>> my_wallet = BitcoinWallet.new_wallet(
        ...     key='correct horse battery staple')
        >>> master_pubkey = my_wallet.get_public_key()
        >>> address = BitcoinWallet.create_address(master_pubkey, 12345)
        >>> address
        u'15wMYnixi2PUSti9pmPgwHya3swDhV19Te'

        Creating a new address is useful for merchants because it allows you to
        link a public bitcoin/altcoin address with a user of your system
        without exposing your private key.

        To create a wallet see `bitmerchant.wallet.Wallet.new_wallet`.

        After backing up the keys, as detailed in Wallet's docs, give the
        master public key of your wallet as a parameter to this method.
        """
        wallet = cls.from_public_key(master_pub_key)
        return wallet.subkey(address_id).address()

    @classmethod
    def from_private_key(cls, key):
        """Load a Wallet from a private key."""
        w = cls.from_wallet_key(key)
        if not w.is_private:
            raise PrivateKeyException("The provided key is not a private key")
        return w

    @classmethod
    def from_public_key(cls, key):
        """Load a Wallet from a public key.

        This Wallet will not have the ability to spend coins, but only to
        generate new addresses at which to receive payments.

            >>> wallet = BitcoinWallet.from_public_key(
            ... u'xpub661MyMwAqRbcFrpiKz9aNJpRkABRXnfREvQqxxya6cdhyGUtx3eRZS'
            ... u'BGXcQgWLg8yY5dpNY2rjwEE6FbXJdqmL37qfkcBNUtbMQfArn7KRg')
            >>> wallet.is_private
            False
        """
        w = cls.from_wallet_key(key)
        if w.is_private:
            raise PublicKeyException("The provided key is a PRIVATE key!")
        return w

    def get_address(self):
        raise NotImplementedError()

    def get_private_key(self):
        """Get the private key for this Wallet.

        DO NOT share this private key with anyone. For maximum security you
        should generate this key on a computer not connected to the internet.
        """
        return self.wallet_key(as_private=True)

    def get_public_key(self):
        """Get the public key for this wallet.

        A public key for a BIP32 wallet allow you to generate new addresses
        without exposing your private key.
        """
        return self.wallet_key(as_private=False)

    def get_keys(self):
        """Get the keys necessary to rebuild this Wallet.

        If this is called on a public-only wallet, the first element of
        the returned tuple will be None. Note, though, that
        self.get_private_key() will have actually thrown an error in this
        case.

        >>> wallet = BitcoinWallet.new_wallet(
        ...     key='correct horse battery staple')
        >>> private, public = wallet.get_keys()
        >>> private  # doctest: +ELLIPSIS
        u'xprv9s21ZrQH143K2mDJW8vDeFwbyDbFv868mM2Zr87rJSTj8q16Unka...'
        >>> public  # doctest: +ELLIPSIS
        u'xpub661MyMwAqRbcFFHmcATE1PtLXFRkKaoz8ZxAeWXTrmzi1dLF2L4q...'
        >>> BitcoinWallet.from_public_key(wallet.get_public_key()).get_keys()
        ... # doctest: +ELLIPSIS
        (None, u'xpub661MyMwAqRbcFFHmcATE1PtLXFRkKaoz8ZxAeWXTrmzi1dLF2L4q...')
        """
        try:
            private = self.get_private_key()
        except wallet.PublicPrivateMismatchError:
            private = None
        public = self.get_public_key()
        return private, public

    def _private_byte_prefix(self):
        def private_byte_prefix(is_test):
            if is_test:
                return chr(self.TEST_PRIVATE_KEY_PREFIX)
            return chr(self.PRIVATE_KEY_PREFIX)
        return private_byte_prefix

    def _public_byte_prefix(self):
        def public_byte_prefix(is_test):
            if is_test:
                return chr(self.TEST_PUBKEY_HASH_PREFIX)
            return chr(self.PUBKEY_HASH_PREFIX)
        return public_byte_prefix

    def address(self, compressed=True):
        with patch('pycoin.encoding.private_byte_prefix',
                   self._private_byte_prefix()):
            with patch('pycoin.encoding.public_byte_prefix',
                       self._public_byte_prefix()):
                return self.bitcoin_address(compressed)

    def __eq__(self, other):
        eq = (self.__class__ is other.__class__ and
              self.get_keys() == other.get_keys() and
              self.is_private == other.is_private and
              self.public_pair == other.public_pair and
              self.chain_code == other.chain_code and
              self.depth == other.depth and
              self.parent_fingerprint == other.parent_fingerprint and
              self.child_number == other.child_number)

        if self.is_private:
            eq = eq and (
                self.secret_exponent == other.secret_exponent)

        return eq

    def __ne__(self, other):
        return not self.__eq__(other)

    def _no_ordering(self):
        raise TypeError("Objects of this type have no ordering")

    def __lt__(self, other):
        self._no_ordering()

    def __le__(self, other):
        self._no_ordering()

    def __gt__(self, other):
        self._no_ordering()

    def __ge__(self, other):
        self._no_ordering()


class BitcoinWallet(_Wallet):
    """BIP32 wallet for BTC"""

    # Byte prefixes
    # Bitcoin (https://en.bitcoin.it/wiki/List_of_address_prefixes)
    # Peercoin, Primecoin and Zetacoin use the same constants.
    # These constants & those below taken, but verified, from
    # https://github.com/matja/bitcoin-tool/blob/master/ec.h
    PUBKEY_HASH_PREFIX = 0
    SCRIPT_HASH_PREFIX = 5
    PRIVATE_KEY_PREFIX = 128
    TEST_PUBKEY_HASH_PREFIX = 111
    TEST_SCRIPT_HASH_PREFIX = 196
    TEST_PRIVATE_KEY_PREFIX = 239


class PeercoinWallet(BitcoinWallet):
    """Wallet for Peercoin."""


class PrimecoinWallet(BitcoinWallet):
    """Wallet for PrimeCoin."""


class ZetacoinWallet(BitcoinWallet):
    """Wallet for Zetacoin."""


class LitecoinWallet(_Wallet):
    """Wallet for Litecoin."""

    # public keys / script:
    # https://github.com/litecoin-project/litecoin/blob/88e2a2e8988b89f905145bdc9af8c34028d0af90/src/base58.h#L275  # nopep8
    # private keys:
    # https://github.com/litecoin-project/litecoin/blob/88e2a2e8988b89f905145bdc9af8c34028d0af90/src/base58.h#L403  # nopep8
    PUBKEY_HASH_PREFIX = 48
    SCRIPT_HASH_PREFIX = 5
    PRIVATE_KEY_PREFIX = PUBKEY_HASH_PREFIX + 128
    TEST_PUBKEY_HASH_PREFIX = 111
    TEST_SCRIPT_HASH_PREFIX = 196
    TEST_PRIVATE_KEY_PREFIX = TEST_PUBKEY_HASH_PREFIX + 128


class DogecoinWallet(_Wallet):
    """Wallet for Dogecoin."""

    # public keys / script:
    # https://github.com/dogecoin/dogecoin/blob/25d26b4848267372ef5b9f6f91480d244afd6884/src/base58.h#L281  # nopep8
    # private keys:
    # https://github.com/dogecoin/dogecoin/blob/25d26b4848267372ef5b9f6f91480d244afd6884/src/base58.h#L409  # nopep8
    PUBKEY_HASH_PREFIX = 30
    SCRIPT_HASH_PREFIX = 22
    PRIVATE_KEY_PREFIX = PUBKEY_HASH_PREFIX + 128
    TEST_PUBKEY_HASH_PREFIX = 113
    TEST_SCRIPT_HASH_PREFIX = 196
    TEST_PRIVATE_KEY_PREFIX = TEST_PUBKEY_HASH_PREFIX + 12


class PrivateKeyException(Exception):
    """Exception for problems with a private key."""


class PublicKeyException(Exception):
    """Exception for problems with a public key."""
