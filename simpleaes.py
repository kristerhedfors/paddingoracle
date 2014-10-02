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


class _SimpleAES(object):
    @classmethod
    def new_salt(self):
        return Random.new().read(self.key_size)

    @classmethod
    def new_iv(self):
        return Random.new().read(AES.block_size)


class SimpleAES(_SimpleAES):
    '''
        AES CBC PKCS#7

        Note that arguments `salt` and `c` are used exclusively for key
        expansion with the PBKDF2 function. Setting `salt` but leaving c=0
        raises an exception as salt will have no effect unless c > 0.
    '''
    key_size = 32

    def __init__(self,
                 key,
                 iv=_SimpleAES.new_iv(),
                 salt=None,
                 c=0):

        self._key = key
        self._iv = iv
        self._salt = salt
        self._c = c
        if (salt and not c) or (c and not salt):
            errmsg = 'salt requires c > 0 and vice versa'
            raise SimpleAESException(errmsg)

    def new_cipher(self, **kw):
        iv = kw.get('iv', self._iv)
        salt = kw.get('salt', self._salt)
        c = kw.get('c', self._c)
        key = self._derive_key(self._key, salt, c)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher

    def _derive_key(self, inkey, salt, c):
        if not salt and not c:
            return inkey
        elif (salt and not c) or (c and not salt):
            errmsg = 'salt requires c > 0 and vice versa'
            raise SimpleAESException(errmsg)
        key = PBKDF2(inkey, salt, self.key_size, self._c)
        return key

    def _pkcs7_encode(self, data):
        _pcount = 16 - (len(data) % 16)
        pkcs7 = data + chr(_pcount) * _pcount
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

    def _encrypt(self, plaintext, **kw):
        pkcs7 = self._pkcs7_encode(plaintext)
        cipher = self.new_cipher(**kw)
        ciphertext = cipher.encrypt(pkcs7)
        return ciphertext

    def _decrypt(self, ciphertext, **kw):
        cipher = self.new_cipher(**kw)
        pkcs7 = cipher.decrypt(ciphertext)
        plaintext = self._pkcs7_decode(pkcs7)
        return plaintext

    def _tostring(self, val):
        if isinstance(val, array.array):
            val = val.tostring()
        elif type(val) is str:
            pass
        else:
            errmsg = 'Only arrays and strings are accepted (not {0}).'
            errmsg = errmsg.format(type(val))
            raise SimpleAESException(errmsg)
        return val

    def encrypt(self, plaintext, **kw):
        plaintext = self._tostring(plaintext)
        return self._encrypt(plaintext, **kw)

    def decrypt(self, ciphertext, **kw):
        ciphertext = self._tostring(ciphertext)
        return self._decrypt(ciphertext, **kw)


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
                salt = SimpleAES.new_salt()
                aes = SimpleAES(key=key, iv=iv, salt=salt, c=c)
                ct = aes.encrypt(pt)
                assert ct != v['ciphertext']
                pt = aes.decrypt(ct)
                assert pt == v['plaintext']

    def test_cipher_padding_errors(self):
        from operator import itemgetter
        from aes_cbc_pkcs7_testdata import vectors
        for c in xrange(1, 32):
            for v in vectors:
                key, iv, ct = itemgetter('key', 'IV', 'ciphertext')(v)
                salt = SimpleAES.new_salt()
                aes = SimpleAES(key=key, iv=iv, salt=salt, c=c)
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

