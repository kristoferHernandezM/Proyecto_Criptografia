from src.feistel_core import encrypt_ctr, decrypt_ctr
import os, hashlib

def test_integridad():
    password = "testpass"
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000, dklen=16)
    
    sample = b"Datos de prueba para algoritmo Feistel." * 10
    nonce = os.urandom(8)

    ct = encrypt_ctr(sample, key, nonce)
    pt = decrypt_ctr(ct, key, nonce)

    assert pt == sample
