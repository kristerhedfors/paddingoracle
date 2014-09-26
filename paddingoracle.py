#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright(c) 2013 Krister Hedfors
#
import unittest
import array

from simpleaes import SimpleAES
from simpleaes import PaddingError


def raises(ex, fn, *args, **kw):
    try:
        fn(*args, **kw)
    except ex:
        return True
    return False


class IOracle(object):
    PaddingError = 0
    Success = 1

    def test(self, value):
        raise Exception('Not implemented, return PaddingError or Success!')

    def get_blocks(self):
        raise Exception('Not implemented, return list')


class PaddingOracleSolver(object):

    def __init__(self, oracle_factory, *args, **kw):
        self._oracle_factory = oracle_factory
        self._args_kw = (args, kw)

    def _new_oracle(self):
        (args, kw) = self._args_kw
        return self._oracle_factory(*args, **kw)

    def _decrypt_block(self, oracle, C1, C2):
        C1x = array.array('B', '\x00' * 16)
        P2 = array.array('B', '\x00' * 16)
        I2 = array.array('B', '\x00' * 16)
        #
        # find the right byte, start from end of block
        #
        for i in xrange(15, -1, -1):
            found = False
            for u in xrange(256):
                C1x[i] = u
                if oracle.test(C1x + C2) == IOracle.Success:
                    found = True
                    break
            assert found

            I2[i] = C1x[i] ^ (16 - i)

            P2[i] = C1[i] ^ I2[i]

            for j in xrange(i, 16):
                C1x[j] = (17 - i) ^ I2[j]
        return P2

    def _get_intermediate(self, oracle, C2):
        C1x = array.array('B', '\x00' * 16)
        I2 = array.array('B', '\x00' * 16)
        #
        # find the right byte
        #
        for i in xrange(15, -1, -1):
            found = False
            for u in xrange(256):
                C1x[i] = u
                if oracle.test(C1x + C2) == IOracle.Success:
                    found = True
                    break
            assert found
            I2[i] = C1x[i] ^ (16 - i)
            for j in xrange(i, 16):
                C1x[j] = (17 - i) ^ I2[j]
        return I2

    def _remove_padding(self, pt):
        n = pt[-1]
        pt = pt[:-n]
        return pt

    def solve(self, ciphertext):
        oracle = self._new_oracle()
        blocks = oracle.get_blocks(ciphertext)
        for i in xrange(len(blocks)):
            if type(blocks[i]) is str:
                blocks[i] = array.array('B', blocks[i])
        i = len(blocks) - 1
        ptlist = []
        while i > 0:
            C1 = blocks[i - 1]
            C2 = blocks[i]
            P2 = self._decrypt_block(oracle, C1, C2)
            ptlist.insert(0, P2)
            i -= 1
        pt = reduce(lambda a, b: a + b, ptlist)
        pt = self._remove_padding(pt)
        intm = self._get_intermediate(oracle, C1)
        return (intm, pt)


class Test_PaddingOracleSolver(unittest.TestCase):

    class MyOracle(IOracle):
        def __init__(self, aes):
            self._aes = aes

        def test(self, value):
            if raises(PaddingError, lambda: self._aes.decrypt(value)):
                return IOracle.PaddingError
            else:
                return IOracle.Success

        def get_blocks(self, value):
            lst = []
            while len(value):
                lst.append(value[:16])
                value = value[16:]
            return lst

    def test_solve1(self):
        MyOracle = self.__class__.MyOracle
        #
        # SimpleAES defaults to using a strong random IV
        # and, if pbkdf2_c > 0, a strong random salt for
        # key expansion.
        #
        aes = SimpleAES('password', pbkdf2_c=1)
        pa_solver = PaddingOracleSolver(MyOracle, aes)
        plaintext = 'Kun avasin Saatana saapuu Moskovaan -kirjan kannet.'
        plaintext += ' Ei paljon puuttunut perunamuusi ja perse.'
        ciphertext = aes.encrypt(plaintext)
        (intm, pt) = pa_solver.solve(ciphertext)
        pt = pt.tostring()

        assert len(pt) == len(plaintext) - 16
        assert pt == plaintext[16:]

        print 'first block (possibly xor:ed with unknown IV):'
        print ' ', intm.tostring().encode('hex')
        print 'all following blocks:'
        print ' ', repr(pt)

    def test_solve_vectors(self):
        from aes_cbc_pkcs7_testdata import vectors
        MyOracle = self.__class__.MyOracle
        for v in vectors:
            if len(v['plaintext']) < 16:
                continue
            aes = SimpleAES(key=v['key'], iv=v['IV'], pbkdf2_c=0)
            pa_solver = PaddingOracleSolver(MyOracle, aes)
            (intm, pt) = pa_solver.solve(v['ciphertext'])
            pt = pt.tostring()

            assert len(pt) == len(v['plaintext']) - 16
            assert pt == v['plaintext'][16:]

            print 'first block (possibly xor:ed with unknown IV):'
            print ' ', intm.tostring().encode('hex')
            print ' ', v['plaintext'][:16].encode('hex')
            print 'all following blocks:'
            print ' ', repr(pt)


def _test():
    import doctest
    import unittest
    print(doctest.testmod())
    unittest.main()

if __name__ == "__main__":
    _test()

