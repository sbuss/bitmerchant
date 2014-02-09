import binascii
from mock import patch
from unittest import TestCase

from bitmerchant.wallet.keys import PrivateKey
from bitmerchant.wallet.keys import BitcoinTestnetKeyConstants
from bitmerchant.wallet.keys import WIFKey


class TestPrivateKey(TestCase):
    def setUp(self):
        # This private key chosen from the bitcoin docs:
        # https://en.bitcoin.it/wiki/Wallet_import_format
        self.key = PrivateKey(
            "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D")


class TestWIF(TestPrivateKey):
    def test_export_to_wif(self):
        self.assertEqual(
            self.key.export_to_wif(),
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")

    def test_import_wif(self):
        key = PrivateKey.from_wif(
            '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        self.assertEqual(key, self.key)

    def test_import_wif_invalid_network(self):
        self.assertRaises(
            WIFKey.IncompatibleNetworkException, PrivateKey.from_wif,
            self.key.export_to_wif(), BitcoinTestnetKeyConstants)

    def test_import_wif_network(self):
        # Make a wif for bitcoin testnet:
        testnet_key = PrivateKey(
            raw_key=self.key.raw_key, constants=BitcoinTestnetKeyConstants)
        testnet_wif = testnet_key.export_to_wif()
        key = PrivateKey.from_wif(testnet_wif, BitcoinTestnetKeyConstants)
        self.assertEqual(testnet_key, key)

    def test_bad_checksum(self):
        with patch('bitmerchant.wallet.keys.WIFKey._wif_checksum',
                   return_value=binascii.unhexlify('FFFFFFFF')):
            wif = self.key.export_to_wif()

        self.assertRaises(WIFKey.ChecksumException, PrivateKey.from_wif, wif)
