from src.feistel_core import encrypt_ctr
import os, hashlib

def test_efecto_avalancha():
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', b"pass", salt, 200000, dklen=16)

    m1 = b"A" * 128
    m2 = bytearray(m1)
    m2[0] ^= 0x01

    nonce = os.urandom(8)

    ct1 = encrypt_ctr(m1, key, nonce)
    ct2 = encrypt_ctr(bytes(m2), key, nonce)

    diff = sum(bin(a ^ b).count("1") for a, b in zip(ct1, ct2))
    assert diff > 0     # límite razonable para avalancha
