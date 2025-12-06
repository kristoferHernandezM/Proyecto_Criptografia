# src/cli.py
import argparse, os, sys, time, hashlib
from pathlib import Path
from src import feistel_core

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "sandbox"
ESCROW_DIR = ROOT / "escrow"
LOG = ROOT / "execution.log"

def log(msg):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    print(line)
    try:
        with open(LOG, "a", encoding='utf-8') as f:
            f.write(line + "\n")
    except Exception:
        pass

def ensure_sandbox(path: Path):
    """Verifica que el archivo esté dentro de /sandbox."""
    path = path.resolve()
    if SANDBOX not in path.parents and path != SANDBOX:
        log(f"ABORTAR: La aplicación solo puede operar dentro de {SANDBOX}")
        sys.exit(1)
    return path

# ---------------------------------------------------------------------
# INIT: genera clave maestra
# ---------------------------------------------------------------------
def cmd_init(args):
    SANDBOX.mkdir(exist_ok=True)
    ESCROW_DIR.mkdir(exist_ok=True)

    key = os.urandom(16)
    with open(SANDBOX / "key.bin", "wb") as f:
        f.write(key)

    log(f"Inicialización completa: clave guardada en {SANDBOX / 'key.bin'}")

# ---------------------------------------------------------------------
# ENCRIPTAR
# ---------------------------------------------------------------------
def cmd_encrypt(args):
    infile = ensure_sandbox(Path(args.input))
    outfile = ensure_sandbox(Path(args.output))

    if not infile.exists():
        log("ERROR: Archivo de entrada no encontrado.")
        sys.exit(1)

    data = infile.read_bytes()

    # Derivación de clave si se usa contraseña
    if args.password:
        salt = os.urandom(16)
        master_key = hashlib.pbkdf2_hmac(
            'sha256', args.password.encode(), salt, 200000, dklen=16
        )
    else:
        master_key = open(SANDBOX / "key.bin", "rb").read()
        salt = os.urandom(16)

    nonce = os.urandom(8)

    ct = feistel_core.encrypt_ctr(data, master_key, nonce)

    with open(outfile, "wb") as f:
        f.write(b"AKATS1" + salt + nonce + ct)
    log(f"Encriptado exitoso: {infile} → {outfile}")

# ---------------------------------------------------------------------
# DESENCRIPTAR
# ---------------------------------------------------------------------
def cmd_decrypt(args):
    infile = ensure_sandbox(Path(args.input))
    outfile = ensure_sandbox(Path(args.output))

    if not infile.exists():
        log("ERROR: Archivo encriptado no encontrado.")
        sys.exit(1)

    raw = infile.read_bytes()

    if not raw.startswith(b"AKATS1"):
        log("ERROR: Formato del archivo inválido o corrupto.")
        sys.exit(1)

    salt = raw[6:22]
    nonce = raw[22:30]
    ct = raw[30:]

    if args.password:
        master_key = hashlib.pbkdf2_hmac(
            'sha256', args.password.encode(), salt, 200000, dklen=16
        )
    else:
        master_key = open(SANDBOX / "key.bin", "rb").read()

    pt = feistel_core.decrypt_ctr(ct, master_key, nonce)

    with open(outfile, "wb") as f:
        f.write(pt)

    log(f"Desencriptado exitoso: {infile} → {outfile}")

# ---------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------
def cmd_test(args):
    log("Iniciando pruebas automáticas...")

    pw = args.password if args.password else "testpass"
    salt = os.urandom(16)

    master_key = hashlib.pbkdf2_hmac(
        'sha256', pw.encode(), salt, 200000, dklen=16
    )

    sample = b"Datos de prueba para algoritmo Feistel." * 40
    nonce = os.urandom(8)

    ct = feistel_core.encrypt_ctr(sample, master_key, nonce)
    pt = feistel_core.decrypt_ctr(ct, master_key, nonce)

    # Integridad
    if pt == sample:
        log("Prueba de integridad: EXITOSA")
    else:
        log("Prueba de integridad: FALLÓ")

    # Avalancha
    m2 = bytearray(sample)
    m2[0] ^= 0x01
    ct2 = feistel_core.encrypt_ctr(bytes(m2), master_key, nonce)
    diff = sum(bin(a ^ b).count('1') for a, b in zip(ct, ct2))

    log(f"Prueba de avalancha: {diff} bits diferentes de {len(ct)*8}")

    # Entropía
    from collections import Counter
    import math

    def entropy(data):
        c = Counter(data)
        l = len(data)
        return -sum((v/l) * math.log2(v/l) for v in c.values())

    ent = entropy(ct)
    log(f"Entropía del cifrado: {ent:.4f} bits por byte")

    log("Pruebas finalizadas.")

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="CLI del algoritmo Feistel — Proyecto Criptografía"
    )

    sub = parser.add_subparsers(dest='cmd')

    # init
    p_init = sub.add_parser('init', help="Inicializa la clave maestra")
    p_init.set_defaults(func=cmd_init)

    # encrypt
    p_enc = sub.add_parser('encrypt', help="Encripta un archivo dentro del sandbox")
    p_enc.add_argument('--input', required=True, help="Archivo de entrada")
    p_enc.add_argument('--output', required=True, help="Archivo de salida")
    p_enc.add_argument('--password', required=False, help="Contraseña opcional")
    p_enc.set_defaults(func=cmd_encrypt)

    # decrypt
    p_dec = sub.add_parser('decrypt', help="Desencripta un archivo dentro del sandbox")
    p_dec.add_argument('--input', required=True, help="Archivo encriptado")
    p_dec.add_argument('--output', required=True, help="Archivo desencriptado")
    p_dec.add_argument('--password', required=False, help="Contraseña opcional")
    p_dec.set_defaults(func=cmd_decrypt)

    # test
    p_test = sub.add_parser('test', help="Ejecuta pruebas del algoritmo")
    p_test.add_argument('--password', required=False)
    p_test.set_defaults(func=cmd_test)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
