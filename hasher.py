#!/usr/bin/env python3

import hashlib
import sys
import base22
import os.path

def sha256file(fname):
    hasher = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.digest()

def hexsha256file(fname):
    hasher = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

for f in sys.argv[1:]:
    if not os.path.isfile(f):
        continue
    sys.stdout.write(f+'\t')
    x = hexsha256file(f)
    sys.stdout.write(x+'\t')
    b = sha256file(f)
    h = base22.bytearray_to_base22(b)
    sys.stdout.write(h+'\n')
