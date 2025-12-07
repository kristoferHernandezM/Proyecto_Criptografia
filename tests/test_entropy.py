from src.feistel_core import encrypt_ctr
import os, hashlib, math
from collections import Counter

def entropy(data):
    c = Counter(data)
    l = len(data)
    return -sum((v/l)*math.log2(v/l) for v in c.values())

def test_entropia_minima():
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', b"pass", salt, 200000, dklen=16)
    nonce = os.urandom(8)

    data = b"TEST" * 200
    ct = encrypt_ctr(data, key, nonce)

    ent = entropy(ct)
    assert ent > 7.0        # aceptable para cifrado casero
