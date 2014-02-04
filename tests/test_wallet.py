import random
from unittest import TestCase

from bitmerchant.wallet.bip32 import _random_wallet_secret
from bitmerchant.wallet.bip32 import create_address
from bitmerchant.wallet.bip32 import new_wallet
from bitmerchant.wallet.bip32 import Wallet


class _TestWalletBase(TestCase):
    def setUp(self):
        self.key = 'correct horse battery staple'
        self.wallet = new_wallet(self.key)


class TestWalletKeys(_TestWalletBase):
    def test_private_key_export(self):
        self.assertEqual(
            self.wallet.get_private_key(),
            (u'xprv9s21ZrQH143K2mDJW8vDeFwbyDbFv868mM2Zr87rJSTj8q16Unka'
             u'q1pryiVYJ3gvoGtazbgKYs1v8rByDYg4LPpQPL6jHjwwhv7DWhWjyXo'))

    def test_wallet_from_private_key(self):
        pk = self.wallet.get_private_key()
        wallet = Wallet.from_private_key(pk)
        self.assertEqual(self.wallet, wallet)
        self.assertTrue(wallet.is_private)

    def test_public_key_export(self):
        self.assertEqual(
            self.wallet.get_public_key(),
            (u'xpub661MyMwAqRbcFFHmcATE1PtLXFRkKaoz8ZxAeWXTrmzi1dLF2L4q'
             u'Np9LpztfGPdCWGmtAqKbgxNAVKxbNxoosK1aQxS995eweD5vi3sfWnz'))

    def test_wallet_from_public_key(self):
        pubkey = self.wallet.get_public_key()
        wallet = Wallet.from_public_key(pubkey)
        self.assertEqual(pubkey, wallet.get_public_key())
        self.assertFalse(wallet.is_private)


class TestWalletComparisons(_TestWalletBase):
    def test_eq_same_key(self):
        """Wallets created with the same master key should be equal."""
        wallet = new_wallet(self.key)
        self.assertEqual(self.wallet, wallet)
        self.assertFalse(self.wallet != wallet)

    def test_eq_same_private_key(self):
        """Wallets created via a private key should be equal."""
        wallet = Wallet.from_private_key(self.wallet.get_private_key())
        self.assertEqual(self.wallet, wallet)
        self.assertFalse(self.wallet != wallet)

    def test_not_equal_diff_key(self):
        """Wallets created with different master keys are not equal."""
        key = "%s1" % self.key
        wallet = new_wallet(key)
        self.assertNotEqual(self.wallet, wallet)
        self.assertFalse(self.wallet == wallet)

    def test_not_equal_private_public_key(self):
        pubkey = self.wallet.get_public_key()
        wallet = Wallet.from_public_key(pubkey)
        self.assertNotEqual(self.wallet, wallet)
        self.assertEqual(wallet.get_public_key(),
                         self.wallet.get_public_key())

    def test_fail_lt(self):
        self.assertRaises(TypeError, self.wallet.__lt__, self.wallet)

    def test_fail_le(self):
        self.assertRaises(TypeError, self.wallet.__le__, self.wallet)

    def test_fail_gt(self):
        self.assertRaises(TypeError, self.wallet.__gt__, self.wallet)

    def test_fail_ge(self):
        self.assertRaises(TypeError, self.wallet.__ge__, self.wallet)


class TestAddressCreation(_TestWalletBase):
    def setUp(self):
        super(TestAddressCreation, self).setUp()
        self.pubkey = self.wallet.get_public_key()

    def test_creation_same_result(self):
        self.assertEqual(
            create_address(self.pubkey, 1),
            create_address(self.pubkey, 1))

    def test_same_as_calling_subkey_directly(self):
        direct = self.wallet.subkey(1).bitcoin_address()
        loaded = create_address(self.pubkey, 1)
        self.assertEqual(direct, loaded)

    def test_different(self):
        self.assertNotEqual(
            create_address(self.pubkey, 1),
            create_address(self.pubkey, 2))

    def test_big_number(self):
        number = 18375283
        direct = self.wallet.subkey(number).bitcoin_address()
        loaded = create_address(self.pubkey, number)
        self.assertEqual(direct, loaded)


class TestRandomSecret(TestCase):
    def test_subsequent_calls_different_results(self):
        result1 = _random_wallet_secret()
        result2 = _random_wallet_secret()
        self.assertNotEqual(result1, result2)

    def test_random_seed(self):
        random.seed(1234567)
        result1 = _random_wallet_secret()
        self.assertNotEqual(result1, _random_wallet_secret())
        random.seed(1234567)
        self.assertEqual(result1, _random_wallet_secret())


def load_tests(loader, tests, ignore):
    """Add doctests to the test suite."""
    import doctest
    from bitmerchant.bip32 import wallet
    tests.addTests(doctest.DocTestSuite(wallet))
    return tests
