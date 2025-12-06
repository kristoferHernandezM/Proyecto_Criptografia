# src/feistel_core.py
import os
import hashlib

BLOCK_SIZE = 16  # 128 bits
HALF = BLOCK_SIZE // 2
ROUNDS = 16


# ---------------------------------------------------------
# Generación de subclaves (key schedule)
# ---------------------------------------------------------
def key_schedule(master_key: bytes):
    subkeys = []
    for r in range(ROUNDS):
        h = hashlib.sha256(master_key + bytes([r])).digest()
        subkeys.append(h[:8])  # 64 bits por ronda
    return subkeys


# ---------------------------------------------------------
# Función F (sin cadena fija, ahora derivada matemáticamente)
# ---------------------------------------------------------
def F_function(subkey: bytes, right: bytes) -> bytes:
    # Hash base
    h = hashlib.sha256(subkey + right).digest()[:8]

    # Constante generada matemáticamente (derivada, no fija)
    const = hashlib.sha256(subkey).digest()[:8]

    # XOR seguro
    out = bytes((h[i] ^ const[i]) & 0xFF for i in range(8))
    return out


# ---------------------------------------------------------
# Cifrado por bloques Feistel
# ---------------------------------------------------------
def encrypt_block(block: bytes, master_key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("El bloque debe medir exactamente 16 bytes")

    L = block[:HALF]
    R = block[HALF:]

    subkeys = key_schedule(master_key)

    for k in subkeys:
        F = F_function(k, R)
        newL = R
        newR = bytes(a ^ b for a, b in zip(L, F))
        L, R = newL, newR

    return R + L


def decrypt_block(block: bytes, master_key: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError("El bloque debe medir exactamente 16 bytes")

    R = block[:HALF]
    L = block[HALF:]

    subkeys = key_schedule(master_key)

    for k in reversed(subkeys):
        F = F_function(k, R)
        newR = bytes(a ^ b for a, b in zip(L, F))
        newL = R
        R, L = newR, newL

    return L + R


# ---------------------------------------------------------
# Modo CTR para cifrar archivos completos
# ---------------------------------------------------------
def encrypt_ctr(plaintext: bytes, master_key: bytes, nonce: bytes) -> bytes:
    if len(nonce) != 8:
        raise ValueError("El nonce debe medir exactamente 8 bytes")

    ciphertext = bytearray()
    counter = 0

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i+BLOCK_SIZE]
        ctr_block = nonce + counter.to_bytes(8, "big")

        keystream = encrypt_block(ctr_block, master_key)
        out = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))

        ciphertext.extend(out)
        counter += 1

    return bytes(ciphertext)


def decrypt_ctr(ciphertext: bytes, master_key: bytes, nonce: bytes) -> bytes:
    # En CTR cifrado y descifrado son iguales
    return encrypt_ctr(ciphertext, master_key, nonce)
