#!/usr/bin/env python3

import sys
import hashlib
import base22
import os.path

def sha256file(fname):
    hasher = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.digest()

f = sys.argv[1]

if not os.path.isfile(f):
    sys.stderr.write('File does not exist: %s\n' % f)
sys.stdout.write(f+'\n')
b = sha256file(f)
for i in range(1, 12+1):
    h = base22.bytearray_to_base22(b, i)
    sys.stdout.write('\t'+h+'\n')
