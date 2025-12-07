from src.feistel_core import encrypt_ctr, decrypt_ctr
import os

def test_ctr_cycle():
    key = os.urandom(16)
    nonce = os.urandom(8)
    msg = b"Hola mundo!" * 20

    ct = encrypt_ctr(msg, key, nonce)
    pt = decrypt_ctr(ct, key, nonce)

    assert pt == msg