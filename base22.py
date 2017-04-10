#!/usr/bin/env python3

import hashlib
from math import log2

BITSPERBYTE = 8

CONSO = 'bcdfghjkmnpqstvwxyz'
VOWEL = 'aeu'
STRLEN = 6
PAIRCOMBINATIONS = len(CONSO)*len(VOWEL)
PAIRCOUNT = int(STRLEN/2)
SINGLECOMBINATIONS = len(CONSO)
SINGLECOUNT = int(STRLEN%2)
# compute number of combinations, assuming CVCVCV... sequence
COMBINATIONS = (PAIRCOMBINATIONS ** PAIRCOUNT) * (SINGLECOMBINATIONS ** SINGLECOUNT)
BITS = int(log2(COMBINATIONS))
MAXNUM = 2**BITS

def getpair(ordval):
    assert ordval >= 0
    assert ordval < PAIRCOMBINATIONS
    consoindex = int( ordval / len(VOWEL) )
    vowelindex = int( ordval % len(VOWEL) )
    return CONSO[consoindex] + VOWEL[vowelindex]

def getsingle(ordval):
    assert ordval >= 0
    assert ordval < SINGLECOMBINATIONS
    consoindex = int( ordval / len(VOWEL) )
    return CONSO[consoindex]

def bytearray_to_base22(b):
    n = 0
    shift = BITS
    byteindex = 0
    while shift > 0:
        shift -= BITSPERBYTE
        if shift >= 0:
            n |= b[byteindex] << shift
        else:
            n |= b[byteindex] >> (-shift)
        byteindex += 1

    s = ''
    divisor = ( PAIRCOMBINATIONS ** (PAIRCOUNT-1) ) * (SINGLECOMBINATIONS ** SINGLECOUNT)
    for i in range(PAIRCOUNT):
        current_number = int(n / divisor)
        s += getpair(current_number)
        n %= divisor
        divisor /= PAIRCOMBINATIONS

    divisor = SINGLECOMBINATIONS ** (SINGLECOUNT-1)
    for i in range(SINGLECOUNT):
        current_number = int(n / divisor)
        s += getsingle(current_number)
        n %= divisor
        divisor /= SINGLECOMBINATIONS

    return s
