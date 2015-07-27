import json
from unittest import TestCase

from bitmerchant.network import BitcoinMainNet, BlockCypherTestNet
from bitmerchant.wallet import Wallet
from bitmerchant.wallet.utils import ensure_bytes


class TestBIP32(TestCase):
    def _test_wallet(self, wallet, data):
        self.assertEqual(
            wallet.serialize_b58(private=True), data['private_key'])
        self.assertEqual(
            wallet.serialize_b58(private=False), data['public_key'])
        self.assertEqual(wallet.export_to_wif(), data['wif'])
        self.assertEqual(wallet.chain_code, ensure_bytes(data['chain_code']))
        fingerprint = ensure_bytes(data['fingerprint'])
        if not fingerprint.startswith(b'0x'):
            fingerprint = b'0x' + fingerprint
        self.assertEqual(wallet.fingerprint, fingerprint)
        self.assertEqual(wallet.depth, data['depth'])
        self.assertEqual(
            wallet.private_key._private_key.privkey.secret_multiplier,
            data['secret_exponent'])

    def _test_file(self, filename, network):
        with open(filename, 'r') as f:
            vectors = json.loads(f.read())
        for wallet_data in vectors:
            wallet = Wallet.deserialize(
                wallet_data['private_key'], network=network)
            self._test_wallet(wallet, wallet_data)
            for child_data in wallet_data['children']:
                child = wallet.get_child_for_path(child_data['path'])
                self._test_wallet(child, child_data['child'])

    def test_bip32_files(self):
        self._test_file(filename="tests/bip32_test_vector.json",
                        network=BitcoinMainNet)
        self._test_file(filename="tests/bip32_blockcypher_test_vector.json",
                        network=BlockCypherTestNet)
