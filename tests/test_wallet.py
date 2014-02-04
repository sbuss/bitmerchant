from unittest import TestCase

from bitmerchant.bip32.wallet import new_wallet
from bitmerchant.bip32.wallet import Wallet


class TestWallet(TestCase):
    def setUp(self):
        self.key = 'correct horse battery staple'
        self.wallet = new_wallet(self.key)

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
        self.assertNotEqual(self.wallet, wallet)
        self.assertEqual(wallet.get_public_key(),
                         self.wallet.get_public_key())
        self.assertFalse(wallet.is_private)
