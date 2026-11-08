from pathlib import Path
import hashlib
from .detect import identify

def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def inventory(paths):
    rows=[]
    for p in paths:
        p=Path(p)
        if p.is_file():
            try: rows.append({"path":str(p),"size":p.stat().st_size,"sha256":sha256(p),"formats":identify(p)})
            except OSError as e: rows.append({"path":str(p),"error":str(e)})
    return rows
