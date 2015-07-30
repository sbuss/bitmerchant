import json

from bitmerchant.network import BitcoinMainNet, BlockCypherTestNet
from bitmerchant.wallet import Wallet
from bitmerchant.wallet.utils import ensure_bytes


def _test_wallet(wallet, data):
    assert wallet.serialize_b58(private=True) == data['private_key']
    assert wallet.serialize_b58(private=False) == data['public_key']
    assert wallet.export_to_wif() == data['wif']
    assert wallet.chain_code == ensure_bytes(data['chain_code'])
    fingerprint = ensure_bytes(data['fingerprint'])
    if not fingerprint.startswith(b'0x'):
        fingerprint = b'0x' + fingerprint
    assert wallet.fingerprint == fingerprint
    assert wallet.depth == data['depth']
    assert wallet.private_key._private_key.privkey.secret_multiplier == \
        data['secret_exponent']


def test_file():
    for filename, network in [
            ("tests/bip32_test_vector.json", BitcoinMainNet),
            ("tests/bip32_blockcypher_test_vector.json", BlockCypherTestNet)]:
        with open(filename, 'r') as f:
            vectors = json.loads(f.read())
        for wallet_data in vectors:
            wallet = Wallet.deserialize(
                wallet_data['private_key'], network=network)
            # use yield for nose test generation
            yield _test_wallet, wallet, wallet_data
            for child_data in wallet_data['children']:
                child = wallet.get_child_for_path(child_data['path'])
                yield _test_wallet, child, child_data['child']
