# src/escrow.py
import os
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Directorio raíz del proyecto
RAIZ = Path(__file__).resolve().parents[1]

# Ruta del archivo de recuperación (escrow)
RUTA_RECUPERACION = RAIZ / 'escrow' / 'recovery.enc'

def crear_escrow(llave_secreta: bytes, contraseña: str):
    """
    Crea un archivo de recuperación cifrado (escrow) usando una passphrase.
    Guarda: salt + nonce + ciphertext
    """
    sal = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=200000
    )

    # KEK = Key Encryption Key (llave derivada de la contraseña)
    llave_kek = kdf.derive(contraseña.encode())

    aesgcm = AESGCM(llave_kek)
    nonce = os.urandom(12)

    # Cifra la llave secreta usando la KEK
    texto_cifrado = aesgcm.encrypt(nonce, llave_secreta, None)

    # Asegurar que el directorio exista
    os.makedirs(RUTA_RECUPERACION.parent, exist_ok=True)

    # Guardar archivo: sal + nonce + ciphertext
    with open(RUTA_RECUPERACION, 'wb') as f:
        f.write(sal + nonce + texto_cifrado)

    return RUTA_RECUPERACION

def recuperar_escrow(contraseña: str):
    """
    Recupera la llave secreta usando la passphrase.
    Lee el archivo y descifra: sal + nonce + ciphertext
    """
    with open(RUTA_RECUPERACION, 'rb') as f:
        datos = f.read()

    sal = datos[:16]
    nonce = datos[16:28]
    texto_cifrado = datos[28:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=sal,
        iterations=200000
    )

    llave_kek = kdf.derive(contraseña.encode())
    aesgcm = AESGCM(llave_kek)

    # Devuelve la llave secreta descifrada
    return aesgcm.decrypt(nonce, texto_cifrado, None)

