import binascii
from unittest import TestCase

import base58

from bitmerchant.wallet.network import BitcoinTestNet
from bitmerchant.wallet.keys import ChecksumException
from bitmerchant.wallet.keys import IncompatibleNetworkException
from bitmerchant.wallet.keys import KeyParseError  # TODO test this
from bitmerchant.wallet.keys import PrivateKey
from bitmerchant.wallet.keys import PublicKey


class _TestPrivateKeyBase(TestCase):
    def setUp(self):
        # This private key chosen from the bitcoin docs:
        # https://en.bitcoin.it/wiki/Wallet_import_format
        self.expected_key = \
            "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
        self.key = PrivateKey(long(self.expected_key, 16))


class _TestPublicKeyBase(TestCase):
    def setUp(self):
        # This private key chosen from the bitcoin docs:
        # https://en.bitcoin.it/wiki/Wallet_import_format
        self.expected_private_key = \
            "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
        self.private_key = PrivateKey(long(self.expected_private_key, 16))
        self.public_key = PublicKey.from_hex_key(
            "04"
            "50863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B2352"
            "2CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6")


class TestPrivateKey(_TestPrivateKeyBase):
    def test_raw_key_hex(self):
        exp = self.key.private_exponent
        self.assertEqual(PrivateKey(exp), self.key)

    def test_raw_key_hex_bytes(self):
        key = binascii.unhexlify(self.key.key)
        self.assertEqual(PrivateKey.from_hex_key(key), self.key)


class TestWIF(_TestPrivateKeyBase):
    def setUp(self):
        super(TestWIF, self).setUp()
        self.expected_wif = \
            '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'

    def test_export_to_wif(self):
        self.assertEqual(
            self.key.export_to_wif(),
            self.expected_wif)

    def test_import_wif(self):
        key = PrivateKey.from_wif(self.expected_wif)
        self.assertEqual(key, self.key)

    def test_import_wif_invalid_network(self):
        self.assertRaises(
            IncompatibleNetworkException, PrivateKey.from_wif,
            self.key.export_to_wif(), BitcoinTestNet)

    def test_import_wif_network(self):
        # Make a wif for bitcoin testnet:
        testnet_key = PrivateKey(
            self.key.private_exponent, network=BitcoinTestNet)
        testnet_wif = testnet_key.export_to_wif()
        # We should be able to load it properly
        key = PrivateKey.from_wif(testnet_wif, BitcoinTestNet)
        self.assertEqual(testnet_key, key)

    def test_bad_checksum(self):
        wif = self.key.export_to_wif()
        bad_checksum = base58.b58encode(binascii.unhexlify('FFFFFFFF'))
        wif = wif[:-8] + bad_checksum
        self.assertRaises(ChecksumException, PrivateKey.from_wif, wif)


class TestPublicKey(_TestPublicKeyBase):
    def test_address(self):
        expected_address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
        actual_address = self.public_key.to_address()
        self.assertEqual(expected_address, actual_address)

    def test_private_to_public(self):
        self.assertEqual(
            self.private_key.get_public_key(),
            self.public_key)

    def test_unhexlified_key(self):
        key_bytes = binascii.unhexlify(self.public_key.key)
        self.assertEqual(
            PublicKey.from_hex_key(key_bytes),
            self.public_key)

    def test_bad_key(self):
        self.assertRaises(KeyParseError, PublicKey.from_hex_key, 'badkey')

    def test_bad_network_key(self):
        key = self.public_key.key
        # Change the network constant
        key = "00" + key[2:]
        self.assertRaises(IncompatibleNetworkException,
                          PublicKey.from_hex_key, key)
