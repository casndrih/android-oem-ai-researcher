"""Read-only MediaTek scatter parser and package image extractor."""
from pathlib import Path
import re, shutil, zipfile

_KEYS = ("partition_name", "file_name", "is_download", "linear_start_addr",
         "physical_start_addr", "partition_size", "region", "storage")

def parse_scatter_text(text: str) -> list[dict]:
    rows=[]; current=None
    for line in text.splitlines():
        m=re.match(r"\s*-\s*partition_index\s*:\s*(.*?)\s*$", line)
        if m:
            if current: rows.append(current)
            current={"partition_index":m.group(1).strip()}; continue
        if current:
            m=re.match(r"\s*([A-Za-z0-9_]+)\s*:\s*(.*?)\s*$", line)
            if m and m.group(1) in _KEYS:
                current[m.group(1)]=m.group(2).strip().strip('"').strip("'")
    if current: rows.append(current)
    return rows

def _safe_relative(name: str) -> str:
    p=Path(name.replace("\\","/"))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise ValueError(f"Unsafe scatter image path: {name}")
    return str(p)

def extract_mtk(source: Path, destination: Path, scatter: Path | None=None) -> list[dict]:
    source, destination=Path(source), Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    if source.is_dir():
        roots=[source]
        if scatter is None:
            found=list(source.rglob("*scatter*.txt"))+list(source.rglob("*scatter*.xml"))
            if not found: raise ValueError("No MediaTek scatter file found")
            scatter=found[0]
        rows=parse_scatter_text(scatter.read_text(encoding="utf-8",errors="replace"))
        results=[]
        for row in rows:
            if row.get("is_download","").lower() not in ("true","1"): continue
            name=row.get("file_name","")
            if not name or name.lower()=="none": continue
            rel=_safe_relative(name)
            candidates=[r/rel for r in roots]
            match=next((p for p in candidates if p.is_file()),None)
            if match is None: continue
            target=destination/Path(rel).name
            if target.exists(): target=destination/f"{row.get('partition_name','partition')}_{target.name}"
            shutil.copyfile(match,target)
            results.append({"partition":row.get("partition_name"),"file":str(target),"size":target.stat().st_size})
        return results
    if not zipfile.is_zipfile(source):
        raise ValueError("MTK input must be an extracted firmware directory or ZIP package")
    with zipfile.ZipFile(source) as z:
        names=z.namelist()
        scatter_name=next((n for n in names if Path(n).name.lower().endswith("scatter.txt")),None)
        if scatter is not None: scatter_text=Path(scatter).read_text(encoding="utf-8",errors="replace")
        elif scatter_name: scatter_text=z.read(scatter_name).decode("utf-8",errors="replace")
        else: raise ValueError("No scatter file found in ZIP; supply --scatter")
        rows=parse_scatter_text(scatter_text); results=[]
        for row in rows:
            if row.get("is_download","").lower() not in ("true","1"): continue
            name=row.get("file_name","")
            if not name or name.lower()=="none": continue
            rel=_safe_relative(name)
            member=next((n for n in names if n.endswith("/"+rel) or n==rel),None)
            if member is None: continue
            target=destination/Path(rel).name
            if target.exists(): target=destination/f"{row.get('partition_name','partition')}_{target.name}"
            with z.open(member) as src, target.open("xb") as dst: shutil.copyfileobj(src,dst,1024*1024)
            results.append({"partition":row.get("partition_name"),"file":str(target),"size":target.stat().st_size})
        return results
