import json

from bitmerchant.network import BitcoinMainNet
from bitmerchant.wallet.keys import PrivateKey
from bitmerchant.wallet.keys import PublicKey


def _test_key(vector):
    private_key = PrivateKey.from_wif(
        vector['private_key'], network=BitcoinMainNet)
    public_key = PublicKey.from_hex_key(
        vector['pubkey'], network=BitcoinMainNet)
    assert private_key.get_public_key() == public_key
    assert public_key.to_address() == vector['address']


def test_keys():
    with open("tests/keys_test_vector.json", 'r') as f:
        vectors = json.loads(f.read())
    for vector in vectors:
        # use yield for nose test generation
        yield _test_key, vector
