import subprocess
from pathlib import Path
import src.cli

def test_cli_encrypt(tmp_path):
    # Creamos archivo en sandbox temporal
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()

    src.cli.SANDBOX = sandbox

    file_in = sandbox / "input.txt"
    file_in.write_text("hola")

    file_out = sandbox / "cifrado.bin"

    # Ejecutar CLI
    result = subprocess.run([
        "python", "-m", "src.cli",
        "encrypt",
        "--input", str(file_in),
        "--output", str(file_out)
    ], capture_output=True, text=True)

    assert file_out.exists()
