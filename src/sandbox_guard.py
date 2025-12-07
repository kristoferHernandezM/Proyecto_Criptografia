# src/sandbox_guard.py
from pathlib import Path

# Directorio raíz (carpeta PROYECTO-CRIPTO)
ROOT = Path(__file__).resolve().parents[1]

# Directorio Sandbox obligatorio
SANDBOX = ROOT / 'sandbox'

def ensure_sandbox_exists():
    """Verifica que el directorio sandbox/ exista."""
    if not SANDBOX.exists():
        raise RuntimeError('ERROR: El directorio sandbox/ no existe.')

def validate_path(path):
    """
    Valida que la ruta dada esté dentro del directorio sandbox.
    Devuelve la ruta normalizada segura.
    """
    p = Path(path).resolve()

    # Python 3.9+: validación segura
    try:
        p.relative_to(SANDBOX)
    except ValueError:
        raise SystemExit(
            f'ABORTAR: Ruta fuera del sandbox.\n'
            f'Intentaste acceder a: {p}\n'
            f'Solo se permite dentro de: {SANDBOX}'
        )

    return p
