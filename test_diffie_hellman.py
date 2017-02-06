import unittest

import diffie_hellman


class DiffieHellmanTestCase(unittest.TestCase):
    # Test vector for 2048-bit MODP Group with 256-bit Prime Order Subgroup defined in RFC 5114
    _x_a = 0x0881382CDB87660C6DC13E614938D5B9C8B2F248581CC5E31B35454397FCE50E
    _y_a = 0x2E9380C8323AF97545BC4941DEB0EC3742C62FE0ECE824A6ABDBE66C59BEE0242911BFB967235CEBA35AE13E4EC752BE630B92DC4BDE2847A9C62CB8152745421FB7EB60A63C0FE9159FCCE726CE7CD8523D7450667EF840E4919121EB5F01C8C9B0D3D648A93BFB75689E8244AC134AF544711CE79A02DCC34226684780DDDCB498594106C37F5BC79856487AF5AB022A2E5E42F09897C1A85A11EA0212AF04D9B4CEBC937C3C1A3E15A8A0342E337615C84E7FE3B8B9B87FB1E73A15AF12A30D746E06DFC34F290D797CE51AA13AA785BF6658AFF5E4B093003CBEAF665B3C2E113A3A4E905269341DC0711426685F4EF37E868A8126FF3F2279B57CA67E29
    _x_b = 0x7D62A7E3EF36DE617B13D1AFB82C780D83A23BD4EE6705645121F371F546A53D
    _y_b = 0x575F0351BD2B1B817448BDF87A6C362C1E289D3903A30B9832C5741FA250363E7ACBC7F77F3DACBC1F131ADD8E03367EFF8FBBB3E1C5784424809B25AFE4D2262A1A6FD2FAB64105CA30A674E07F7809852088632FC049233791AD4EDD083A978B883EE618BC5E0DD047415F2D95E683CF14826B5FBE10D3CE41C6C120C78AB20008C698BF7F0BCAB9D7F407BED0F43AFB2970F57F8D12043963E66DDD320D599AD9936C8F44137C08B180EC5E985CEBE186F3D549677E80607331EE17AF3380A725B0782317D7DD43F59D7AF9568A9BB63A84D365F92244ED120988219302F42924C7CA90B89D24F71B0AB697823D7DEB1AFF5B0E8E4A45D49F7F53757E1913
    _z = 0x86C70BF8D0BB81BB01078A17219CB7D27203DB2A19C877F1D1F19FD7D77EF22546A68F005AD52DC84553B78FC60330BE51EA7C0672CAC1515E4B35C047B9A551B88F39DC26DA14A09EF74774D47C762DD177F9ED5BC2F11E52C879BD95098504CD9EECD8A8F9B3EFBD1F008AC5853097D9D1837F2B18F77CD7BE01AF80A7C7B5EA3CA54CC02D0C116FEE3F95BB87399385875D7E86747E676E728938ACBFF7098E05BE4DCFB24052B83AEFFB14783F029ADBDE7F53FAE92084224090E007CEE94D4BF2BACE9FFD4B57D2AF7C724D0CAA19BF0501F6F17B4AA10F425E3EA76080B4B9D6B3CEFEA115B2CEB8789BB8A3B0EA87FEBE63B6C8F846EC6DB0C26C5D7C

    def test_alice_public(self):
        self.assertEqual(diffie_hellman.get_public_key(self._x_a), self._y_a)

    def test_bob_public(self):
        self.assertEqual(diffie_hellman.get_public_key(self._x_b), self._y_b)

    def test_alice_shared_key(self):
        self.assertEqual(diffie_hellman.get_shared_key(self._y_b, self._x_a), self._z)

    def test_bob_shared_key(self):
        self.assertEqual(diffie_hellman.get_shared_key(self._y_a, self._x_b), self._z)

    def test_long_to_bin_conversions_z(self):
        bin_with_len = diffie_hellman.long_to_bin_with_len(self._z)
        pos, num1 = diffie_hellman.bin_with_len_to_pos_and_long(bin_with_len)
        num2 = diffie_hellman.bin_to_long(bin_with_len[2:])
        test_len = len(hex(self._z)[2:].rstrip('L')) // 2 + (len(hex(self._z)[2:].rstrip('L')) // 2) % 2
        self.assertEqual(diffie_hellman.long_to_bin(self._z), bin_with_len[2:])
        self.assertEqual(pos, len(bin_with_len))
        self.assertEqual(pos - 2, test_len)
        self.assertEqual(num2, self._z)
        self.assertEqual(num1, self._z)

    def test_long_to_bin_conversions_a(self):
        bin_with_len = diffie_hellman.long_to_bin_with_len(self._x_a)
        pos, num1 = diffie_hellman.bin_with_len_to_pos_and_long(bin_with_len)
        num2 = diffie_hellman.bin_to_long(bin_with_len[2:])
        test_len = len(hex(self._x_a)[2:].rstrip('L')) // 2 + (len(hex(self._x_a)[2:].rstrip('L')) // 2) % 2
        self.assertEqual(diffie_hellman.long_to_bin(self._x_a), bin_with_len[2:])
        self.assertEqual(pos, len(bin_with_len))
        self.assertEqual(pos - 2, test_len)
        self.assertEqual(num2, self._x_a)
        self.assertEqual(num1, self._x_a)

    def test_packed_data(self):
        alice_public_packed = diffie_hellman.pack_public_to_bin(diffie_hellman.long_to_bin(self._x_a))
        shared_key_bob, bob_public_packed = diffie_hellman. \
            get_shared_key_and_packed_public(diffie_hellman.long_to_bin(self._x_b), alice_public_packed)
        shared_key_alice, _ = diffie_hellman. \
            get_shared_key_and_packed_public(diffie_hellman.long_to_bin(self._x_a), bob_public_packed)
        self.assertEquals(self._z, diffie_hellman.bin_to_long(shared_key_bob))
        self.assertEquals(self._z, diffie_hellman.bin_to_long(shared_key_alice))


if __name__ == '__main__':
    unittest.main()
