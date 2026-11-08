from pathlib import Path, PurePosixPath
import tarfile, zipfile

def safe_name(name: str) -> bool:
    p=PurePosixPath(name.replace("\\","/"))
    return not p.is_absolute() and ".." not in p.parts and bool(p.parts)

def list_archive(path: Path) -> list[dict]:
    rows=[]
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for i in z.infolist(): rows.append({"name":i.filename,"size":i.file_size,"safe":safe_name(i.filename)})
    elif tarfile.is_tarfile(path):
        with tarfile.open(path,"r:*") as t:
            for m in t.getmembers(): rows.append({"name":m.name,"size":m.size,"safe":safe_name(m.name) and m.isfile()})
    else: raise ValueError("Unsupported archive container")
    return rows

def extract_safe(path: Path, destination: Path) -> list[str]:
    destination=destination.resolve(); written=[]
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if not safe_name(i.filename) or i.is_dir(): continue
                target=(destination/i.filename).resolve()
                if destination not in target.parents: continue
                target.parent.mkdir(parents=True,exist_ok=True)
                with z.open(i) as src, target.open("wb") as dst:
                    while chunk:=src.read(1024*1024): dst.write(chunk)
                written.append(str(target))
    else:
        with tarfile.open(path,"r:*") as t:
            for m in t.getmembers():
                if not m.isfile() or not safe_name(m.name): continue
                target=(destination/m.name).resolve()
                if destination not in target.parents: continue
                src=t.extractfile(m)
                if src is None: continue
                target.parent.mkdir(parents=True,exist_ok=True)
                with src, target.open("wb") as dst:
                    while chunk:=src.read(1024*1024): dst.write(chunk)
                written.append(str(target))
    return written
