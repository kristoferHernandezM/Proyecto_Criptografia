# src/sandbox_guard.py
from pathlib import Path

# Directorio raíz del proyecto
ROOT = Path(__file__).resolve().parents[1]

# Directorio Sandbox obligatorio
SANDBOX = ROOT / 'sandbox'

def ensure_sandbox_exists():
    """Verifica que el directorio sandbox/ exista."""
    if not SANDBOX.exists():
        raise RuntimeError('ERROR: El directorio sandbox/ no existe.')

def validate_path(path):
    """Valida que una ruta dada esté dentro del directorio sandbox."""
    p = Path(path).resolve()

    # Si el archivo NO está dentro de /sandbox → abortar
    if SANDBOX not in p.parents and p != SANDBOX:
        raise SystemExit('ABORTAR: La operación está fuera del directorio sandbox.')

    return p
