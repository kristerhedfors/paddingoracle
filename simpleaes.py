#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2013 Krister Hedfors
#
import unittest
import array

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random


class SimpleAESException(Exception):
    pass


class PaddingError(SimpleAESException):
    pass


class SimpleAES(object):
    'AES CBC PKCS#7'

    key_size = 32

    def __init__(self, key, iv=None, salt=None, pbkdf2_c=0, verbose=0):
        self._key = key
        self._pbkdf2_c = pbkdf2_c
        self._verbose = verbose
        self._iv = iv or self._new_iv()
        self._salt = salt or self._new_salt()
        if salt:
            if not self._pbkdf2_c:
                errmsg = 'salt given but will not be used unless pbkdf2_c > 0'
                raise SimpleAESException(errmsg)

    def _new_salt(self):
        return Random.new().read(self.key_size)

    def _new_iv(self):
        return Random.new().read(AES.block_size)

    def new_cipher(self, iv=None, salt=None):
        key = self._key
        if iv is None:
            iv = self._new_iv()
        if salt is None:
            if not self._pbkdf2_c:
                errmsg = 'salt given but will not be used unless pbkdf2_c > 0'
                raise SimpleAESException(errmsg)
            salt = self._salt
        if self._pbkdf2_c:
            key = PBKDF2(self._key, salt, self.key_size, self._pbkdf2_c)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher

    def _pkcs7_encode(self, data):
        _pcount = 16 - (len(data) % 16)
        pkcs7 = data + chr(_pcount) * _pcount
        if 0 or self._verbose:
            print 'ENCODED', repr(pkcs7)
        return pkcs7

    def _pkcs7_decode(self, pkcs7):
        try:
            assert len(pkcs7)
            assert len(pkcs7) % 16 == 0
            p = ord(pkcs7[-1])
            assert 1 <= p <= 16
            prange = pkcs7[-p:]
            assert prange == chr(p) * p
        except AssertionError:
            raise PaddingError
        data = pkcs7[:-p]
        return data

    def _encrypt(self, plaintext, iv, salt):
        if salt is None:
            salt = self._salt
        if iv is None:
            iv = self._iv
        pkcs7 = self._pkcs7_encode(plaintext)
        cipher = self.new_cipher(iv=iv, salt=salt)
        ciphertext = cipher.encrypt(pkcs7)
        return ciphertext

    def _decrypt(self, ciphertext, iv, salt):
        if iv is None:
            iv = self._iv
        if salt is None:
            salt = self._salt
        # !!! static IV
        cipher = self.new_cipher(iv=iv, salt=salt)
        pkcs7 = cipher.decrypt(ciphertext)
        plaintext = self._pkcs7_decode(pkcs7)
        return plaintext

    def _tostring(self, val):
        if isinstance(val, array.array):
            val = val.tostring()
        return val

    def encrypt(self, plaintext, salt=None, iv=None):
        plaintext = self._tostring(plaintext)
        return self._encrypt(plaintext, iv=iv, salt=salt)

    def decrypt(self, ciphertext, salt=None, iv=None):
        ciphertext = self._tostring(ciphertext)
        return self._decrypt(ciphertext, iv=iv, salt=salt)


def raises(ex, fn, *args, **kw):
    try:
        fn(*args, **kw)
    except ex:
        return True
    return False


class Test_SimpleAES(unittest.TestCase):

    def test_test(self):
        assert 1 == 1

    def test_vectors_simple(self):
        from operator import itemgetter
        from aes_cbc_pkcs7_testdata import vectors
        for v in vectors:
            key, iv, pt = itemgetter('key', 'IV', 'plaintext')(v)
            aes = SimpleAES(key=key, iv=iv)
            ct = aes.encrypt(pt)
            assert ct == v['ciphertext']
            pt = aes.decrypt(ct)
            assert pt == v['plaintext']

    def test_vectors_with_pbkdf2(self):
        from operator import itemgetter
        from aes_cbc_pkcs7_testdata import vectors
        for c in (3, 11, 29, 107, 383):
            for v in vectors:
                key, iv, pt = itemgetter('key', 'IV', 'plaintext')(v)
                aes = SimpleAES(key=key, iv=iv, pbkdf2_c=c)
                ct = aes.encrypt(pt)
                assert ct != v['ciphertext']
                pt = aes.decrypt(ct)
                assert pt == v['plaintext']

    def test_cipher_padding_errors(self):
        from operator import itemgetter
        from aes_cbc_pkcs7_testdata import vectors
        for c in xrange(32):
            for v in vectors:
                key, iv, ct = itemgetter('key', 'IV', 'ciphertext')(v)
                aes = SimpleAES(key=key, iv=iv, pbkdf2_c=c)
                ct = chr((ord(ct[0]) + 1) % 256) + ct[1:]
                try:
                    pt = aes.decrypt(ct)
                except PaddingError:
                    pass
                else:
                    assert pt != v['plaintext']
                    if 0:
                        print len(pt), pt.encode('hex')
                        print len(v['plaintext']), v['plaintext'].encode('hex')
                        print '------'


def _test():
    import doctest
    import unittest
    unittest.main()
    print(doctest.testmod())

if __name__ == "__main__":
    _test()

