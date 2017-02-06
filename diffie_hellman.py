# Copyright (C) 2017 Maxim Avilov (https://github.com/maxavilov)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import binascii
import struct

from Crypto.Protocol.KDF import PBKDF2

# 2048-bit MODP Group with 256-bit Prime Order Subgroup defined in RFC 5114
_p = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
_g = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659


def long_to_bin_with_len(long_val):
    hex_str = hex(long_val)[2:].rstrip('L')
    return struct.pack('>H', len(hex_str) // 2 + (len(hex_str) // 2) % 2) + \
           binascii.unhexlify('0' * (len(hex_str) % 2) + hex_str)


def long_to_bin(long_val):
    hex_str = hex(long_val)[2:].rstrip('L')
    return binascii.unhexlify('0' * (len(hex_str) % 2) + hex_str)


def bin_with_len_to_pos_and_long(bin_with_len, start=0):
    num_len = struct.unpack('>H', bin_with_len[start:start + 2])[0]
    bin_val = bin_with_len[start + 2:start + 2 + num_len]
    try:
        return start + num_len + 2, long(bin_val.encode('hex'), 16)  # Python 2
    except NameError:
        return start + num_len + 2, int.from_bytes(bin_val, byteorder='big')  # Python 3


def bin_to_long(bin_val):
    try:
        return long(bin_val.encode('hex'), 16)  # Python 2
    except NameError:
        return int.from_bytes(bin_val, byteorder='big')  # Python 3


def get_public_key(secret, p=_p, g=_g):
    return pow(g, secret, p)


def get_public_key_from_bin_secret(bin_secret, p=_p, g=_g):
    return get_public_key(bin_to_long(bin_secret), p, g)


def get_shared_key(b_public_key, a_secret, p=_p):
    return pow(b_public_key, a_secret, p)


def get_shared_key_from_bin_secret(b_public_key, a_bin_secret, p=_p):
    return get_shared_key(b_public_key, bin_to_long(a_bin_secret), p)


def pack_public_to_bin(bin_secret):
    return long_to_bin_with_len(get_public_key_from_bin_secret(bin_secret)) + long_to_bin_with_len(
        _p) + long_to_bin_with_len(_g)


def get_shared_key_and_packed_public(alice_bin_secret, bob_packed_public):
    pos, bob_public = bin_with_len_to_pos_and_long(bob_packed_public)
    pos, p = bin_with_len_to_pos_and_long(bob_packed_public, pos)
    _, g = bin_with_len_to_pos_and_long(bob_packed_public, pos)
    alice_public = get_public_key_from_bin_secret(alice_bin_secret, p, g)
    return binascii.unhexlify(hex(get_shared_key_from_bin_secret(bob_public, alice_bin_secret, p))[2:].rstrip('L')), \
           long_to_bin_with_len(alice_public) + long_to_bin_with_len(p) + long_to_bin_with_len(g)


def passphrase_to_secret(passphrase):
    return PBKDF2(passphrase.encode('utf-8'), "HPqbk76Su8adA7rsctq3".encode('utf-8'), dkLen=32, count=100000)


def get_packed_public_from_passphrase(passprase):
    return pack_public_to_bin(passphrase_to_secret(passprase))
