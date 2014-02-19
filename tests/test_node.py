import binascii
from unittest import TestCase

from bitmerchant.wallet.node import Node


class TestNode(TestCase):
    def setUp(self):
        self.expected_key = (
            "0488ade4"  # BitcoinMainNet version
            "00"  # depth
            "00000000"  # parent fingerprint
            "00000000"  # child_number
            # chain_code
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
            "00"  # key identifier
            # private exponent
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
        self.master_key = Node.deserialize(self.expected_key)

    def test_serialize_master_key(self):
        self.assertEqual(self.expected_key, self.master_key.serialize())

    def test_from_master_secret(self):
        secret = binascii.unhexlify('000102030405060708090a0b0c0d0e0f')
        self.assertEqual(Node.from_master_secret(secret),
                         self.master_key)

    def test_invalid_network_prefix(self):
        pass

    def test_invalid_key_data_prefix(self):
        pass

    def test_invalid_fingerprint(self):
        pass

    def test_identifier(self):
        pass

    def test_fingerprint(self):
        pass


class TestNodeVectors(TestCase):
    def setUp(self):
        self.master_key = Node.from_master_secret(
            binascii.unhexlify('000102030405060708090a0b0c0d0e0f'))

    def _test_vector(self, key, id_hex, fingerprint, address,
                     secret_key_hex, secret_key_wif,
                     pubkey_hex, chaincode_hex,
                     pubkey_serialized_hex, private_serialized_hex,
                     pubkey_base58, private_base58,
                     include_private=True
                     ):
        self.assertEqual(key.to_address(), address)
        self.assertEqual(key.get_public_key_hex(), pubkey_hex)
        self.assertEqual(key.chain_code, chaincode_hex)
        self.assertEqual(key.serialize(private=False),
                         pubkey_serialized_hex)
        self.assertEqual(key.serialize_b58(private=False), pubkey_base58)

        if include_private:
            self.assertEqual(key.identifier, id_hex)
            self.assertEqual(key.fingerprint, fingerprint)
            self.assertEqual(key.get_private_key_hex(), secret_key_hex)
            self.assertEqual(key.export_to_wif(), secret_key_wif)
            self.assertEqual(key.serialize(), private_serialized_hex)
            self.assertEqual(key.serialize_b58(), private_base58)

    def test_m(self):
        """[Chain m]"""
        vector = [
            '3442193e1bb70916e914552172cd4e2dbc9df811',
            '0x3442193e',
            '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
            'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
            'L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW',
            '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',  # nopep8
            '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508',
            '0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2',  # nopep8
            '0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',  # nopep8
            'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',  # nopep8
            'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',  # nopep8
        ]
        self._test_vector(self.master_key, *vector)

    def test_m_0p(self):
        vector = [
            '5c1bd648ed23aa5fd50ba52b2457c11e9e80a6a7',
            '0x5c1bd648',
            '19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh',
            'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea',
            'L5BmPijJjrKbiUfG4zbiFKNqkvuJ8usooJmzuD7Z8dkRoTThYnAT',
            '035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56',  # nopep8
            '47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141',
            '0488b21e013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56',  # nopep8
            '0488ade4013442193e8000000047fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae623614100edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea',  # nopep8
            'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',  # nopep8
            'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',  # nopep8
        ]
        key = self.master_key.get_child(0, is_prime=True)
        self._test_vector(key, *vector)

    def test_m_0p_1(self):
        vector = [
            'bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe',
            '0xbef5a2f9',
            '1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj',
            '3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368',
            'KyFAjQ5rgrKvhXvNMtFB5PCSKUYD1yyPEe3xr3T34TZSUHycXtMM',
            '03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c',  # nopep8
            '2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19',
            '0488b21e025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c1903501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c',  # nopep8
            '0488ade4025c1bd648000000012a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19003c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368',  # nopep8
            'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',  # nopep8
            'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',  # nopep8
        ]
        m0 = self.master_key.get_child(0, is_prime=True)
        key = m0.get_child(1, is_prime=False)
        self._test_vector(key, *vector)

    def test_m_0p_1_2p(self):
        vector = [
            'ee7ab90cde56a8c0e2bb086ac49748b8db9dce72',
            '0xee7ab90c',
            '1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x',
            'cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca',
            'L43t3od1Gh7Lj55Bzjj1xDAgJDcL7YFo2nEcNaMGiyRZS1CidBVU',
            '0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2',  # nopep8
            '04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f',
            '0488b21e03bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2',  # nopep8
            '0488ade403bef5a2f98000000204466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f00cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca',  # nopep8
            'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',  # nopep8
            'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',  # nopep8
        ]
        self._test_vector(
            self.master_key.get_child(0, True).get_child(1).get_child(-2),
            *vector)

    def test_m_0p_1_2p_2(self):
        vector = [
            'd880d7d893848509a62d8fb74e32148dac68412f',
            '0xd880d7d8',
            '1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt',
            '0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4',
            'KwjQsVuMjbCP2Zmr3VaFaStav7NvevwjvvkqrWd5Qmh1XVnCteBR',
            '02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29',  # nopep8
            'cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd',
            '0488b21e04ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29',  # nopep8
            '0488ade404ee7ab90c00000002cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd000f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4',  # nopep8
            'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',  # nopep8
            'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',  # nopep8
        ]
        node = self.master_key.get_child(0, True).get_child(1).get_child(-2)
        node = node.get_child(2)
        self._test_vector(node, *vector)

    def test_m_0p_1_2p_2_1000000000(self):
        vector = [
            'd69aa102255fed74378278c7812701ea641fdf32',
            '0xd69aa102',
            '1LZiqrop2HGR4qrH1ULZPyBpU6AUP49Uam',
            '471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8',
            'Kybw8izYevo5xMh1TK7aUr7jHFCxXS1zv8p3oqFz3o2zFbhRXHYs',
            '022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011',  # nopep8
            'c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e',
            '0488b21e05d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011',  # nopep8
            '0488ade405d880d7d83b9aca00c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e00471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8',  # nopep8
            'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',  # nopep8
            'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',  # nopep8
        ]
        node = (self.master_key.get_child(0, True)
                .get_child(1).get_child(-2).get_child(2)
                .get_child(1000000000))
        self._test_vector(node, *vector)
