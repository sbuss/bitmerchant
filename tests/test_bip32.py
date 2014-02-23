import binascii
from unittest import TestCase

from bitmerchant.network import BitcoinMainNet
from bitmerchant.network import BitcoinTestNet
from bitmerchant.wallet import Wallet
from bitmerchant.wallet.keys import IncompatibleNetworkException
from bitmerchant.wallet.utils import long_to_hex


class TestWallet(TestCase):
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
        self.master_key = Wallet.deserialize(self.expected_key)

    def test_serialize_master_key(self):
        self.assertEqual(self.expected_key, self.master_key.serialize())

    def test_from_master_secret(self):
        secret = binascii.unhexlify('000102030405060708090a0b0c0d0e0f')
        self.assertEqual(Wallet.from_master_secret(secret),
                         self.master_key)

    def test_invalid_network_prefix(self):
        key = self.expected_key
        key = (long_to_hex(BitcoinTestNet.EXT_SECRET_KEY, 8) +
               self.expected_key[8:])
        with self.assertRaises(IncompatibleNetworkException):
            Wallet.deserialize(key, BitcoinMainNet)
        self.assertTrue(Wallet.deserialize(key, BitcoinTestNet))

    def test_public_export(self):
        """Export a node as public."""
        child = self.master_key.get_child(0, as_private=False)
        self.assertEqual(child.private_key, None)
        key = child.serialize(False)
        self.assertIn(
            long_to_hex(BitcoinMainNet.EXT_PUBLIC_KEY, 8),
            key)
        self.assertEqual(Wallet.deserialize(key), child)

    def test_public_export_mismatch(self):
        """Can't export a public node as private."""
        child = self.master_key.get_child(0, as_private=False)
        self.assertEqual(child.private_key, None)
        with self.assertRaises(ValueError):
            child.serialize()



class TestSerialize(TestCase):
    def setUp(self):
        self.wallet = Wallet.new_random_wallet()

    def test_serialize_private(self):
        prv = self.wallet.serialize(private=True)
        w = Wallet.deserialize(prv)
        self.assertTrue(w.private_key)
        self.assertEqual(w, self.wallet)

        prv = self.wallet.serialize_b58(private=True)
        w = Wallet.deserialize(prv)
        self.assertTrue(w.private_key)
        self.assertEqual(w, self.wallet)

    def test_serialize_public(self):
        pub = self.wallet.serialize(private=False)
        w = Wallet.deserialize(pub)
        self.assertFalse(w.private_key)

        pub = self.wallet.serialize_b58(private=False)
        w = Wallet.deserialize(pub)
        self.assertFalse(w.private_key)


class _TestWalletVectors(TestCase):
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


class TestWalletVectors1(_TestWalletVectors):
    def setUp(self):
        self.master_key = Wallet.from_master_secret(
            binascii.unhexlify('000102030405060708090a0b0c0d0e0f'))

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


class TestWalletVectors2(_TestWalletVectors):
    def setUp(self):
        self.master_key = Wallet.from_master_secret(binascii.unhexlify(
            'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2'
            '9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'
        ))

    def test_m(self):
        vector = [
            'bd16bee53961a47d6ad888e29545434a89bdfe95',
            '0xbd16bee5',
            '1JEoxevbLLG8cVqeoGKQiAwoWbNYSUyYjg',
            '4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e',
            'KyjXhyHF9wTphBkfpxjL8hkDXDUSbE3tKANT94kXSyh6vn6nKaoy',
            '03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7',  # nopep8
            '60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689',
            '0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7',  # nopep8
            '0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e',  # nopep8
            'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',  # nopep8
            'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',  # nopep8
        ]
        self._test_vector(self.master_key, *vector)

    def test_m_0(self):
        vector = [
            '5a61ff8eb7aaca3010db97ebda76121610b78096',
            '0x5a61ff8e',
            '19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ',
            'abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e',
            'L2ysLrR6KMSAtx7uPqmYpoTeiRzydXBattRXjXz5GDFPrdfPzKbj',
            '02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea',  # nopep8
            'f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c',
            '0488b21e01bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea',  # nopep8
            '0488ade401bd16bee500000000f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c00abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e',  # nopep8
            'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',  # nopep8
            'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',  # nopep8
        ]
        self._test_vector(self.master_key.get_child(0), *vector)

    def test_m_0_2147483647p(self):
        vector = [
            'd8ab493736da02f11ed682f88339e720fb0379d1',
            '0xd8ab4937',
            '1Lke9bXGhn5VPrBuXgN12uGUphrttUErmk',
            '877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93',
            'L1m5VpbXmMp57P3knskwhoMTLdhAAaXiHvnGLMribbfwzVRpz2Sr',
            '03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b',  # nopep8
            'be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9',
            '0488b21e025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d903c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b',  # nopep8
            '0488ade4025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d900877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93',  # nopep8
            'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',  # nopep8
            'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',  # nopep8
        ]
        self._test_vector(self.master_key.get_child(0)
                          .get_child(2147483647, True), *vector)
        self._test_vector(self.master_key.get_child(0)
                          .get_child(-2147483647), *vector)

    def test_m_0_2147483647p_1(self):
        vector = [
            '78412e3a2296a40de124307b6485bd19833e2e34',
            '0x78412e3a',
            '1BxrAr2pHpeBheusmd6fHDP2tSLAUa3qsW',
            '704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7',
            'KzyzXnznxSv249b4KuNkBwowaN3akiNeEHy5FWoPCJpStZbEKXN2',
            '03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9',  # nopep8
            'f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb',
            '0488b21e03d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9',  # nopep8
            '0488ade403d8ab493700000001f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb00704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7',  # nopep8
            'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',  # nopep8
            'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',  # nopep8
        ]
        self._test_vector(self.master_key.get_child(0)
                          .get_child(2147483647, True)
                          .get_child(1), *vector)

    def test_m_0_2147483647p_1_2147483646p(self):
        vector = [
            '31a507b815593dfc51ffc7245ae7e5aee304246e',
            '0x31a507b8',
            '15XVotxCAV7sRx1PSCkQNsGw3W9jT9A94R',
            'f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d',
            'L5KhaMvPYRW1ZoFmRjUtxxPypQ94m6BcDrPhqArhggdaTbbAFJEF',
            '02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0',  # nopep8
            '637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29',
            '0488b21e0478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2902d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0',  # nopep8
            '0488ade40478412e3afffffffe637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e2900f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d',  # nopep8
            'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',  # nopep8
            'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',  # nopep8
        ]
        self._test_vector(self.master_key.get_child(0)
                          .get_child(2147483647, True)
                          .get_child(1)
                          .get_child(2147483646, True), *vector)

    def test_m_0_2147483647p_1_2147483646p_2(self):
        vector = [
            '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220',
            '0x26132fdb',
            '14UKfRV9ZPUp6ZC9PLhqbRtxdihW9em3xt',
            'bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23',
            'L3WAYNAZPxx1fr7KCz7GN9nD5qMBnNiqEJNJMU1z9MMaannAt4aK',
            '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c',  # nopep8
            '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271',
            '0488b21e0531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c',  # nopep8
            '0488ade40531a507b8000000029452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed27100bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23',  # nopep8
            'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',  # nopep8
            'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',  # nopep8
        ]
        self._test_vector(self.master_key.get_child(0)
                          .get_child(2147483647, True)
                          .get_child(1)
                          .get_child(2147483646, True)
                          .get_child(2), *vector)
        self._test_vector(self.master_key.get_child(0)
                          .get_child(-2147483647)
                          .get_child(1)
                          .get_child(-2147483646)
                          .get_child(2), *vector)
