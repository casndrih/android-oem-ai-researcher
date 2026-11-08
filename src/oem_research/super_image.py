"""Safe wrapper around the Android lpunpack utility for dynamic super images.

lpunpack must be installed separately and available on PATH. No shell is used.
"""
from pathlib import Path
import shutil
import subprocess

def unpack_super(source: Path, destination: Path, timeout: int = 600) -> dict:
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    tool = shutil.which("lpunpack")
    if not tool:
        raise RuntimeError("lpunpack was not found on PATH; install Android lpunpack first")
    destination.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [tool, str(source), str(destination)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=timeout, check=False
    )
    if result.returncode:
        raise RuntimeError(f"lpunpack failed ({result.returncode}): {result.stderr[-2000:]}")
    outputs = [{"file": str(p), "size": p.stat().st_size} for p in sorted(destination.iterdir()) if p.is_file()]
    return {"source": str(source), "destination": str(destination), "files": outputs, "stdout": result.stdout[-2000:]}
