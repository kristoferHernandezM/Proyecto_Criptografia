
# tests/test_feistel.py
from src import feistel_core
def test_block_cycle():
    key = b'0123456789abcdef'
    blk = b'01234567ABCDEFGH'
    ct = feistel_core.encrypt_block(blk, key)
    pt = feistel_core.decrypt_block(ct, key)
    assert pt == blk
